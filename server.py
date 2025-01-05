import os
import threading
import subprocess
import time
import json
import csv
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import tempfile
import re
from flask import Flask, render_template
import pandas as pd

# Variables
PORT = 8443
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
CSV_FILE = "/var/www/ftp/system_stats.csv"  # Save CSV to the web-accessible directory
PASSWORD_FILE = "registered_clients.txt"    # File containing registered password hashes (format: username:password_hash)
ACTIVATION_LOG = "/var/www/ftp/activation_log.txt"  # Log file in the web-accessible directory
ASSIGNED_NODES_FILE = "assigned_nodes.txt"  # File containing assigned node IPs
WEB_DIR = "/var/www/ftp"                    # Web-accessible directory

# Ensure the web directory exists
os.makedirs(WEB_DIR, exist_ok=True)
os.chmod(WEB_DIR, 0o755)

# Flask app for the web interface
app = Flask(__name__)

@app.route("/")
def dashboard():
    """Render the dashboard with server stats."""
    try:
        # Read the CSV file into a Pandas DataFrame
        stats_df = pd.read_csv(CSV_FILE)
        # Convert the DataFrame to HTML for rendering
        stats_html = stats_df.to_html(index=False)
    except Exception as e:
        stats_html = f"<p>Error loading stats: {e}</p>"
    return render_template("dashboard.html", stats_table=stats_html)

def run_flask_app():
    """Run the Flask web interface on port 5000."""
    app.run(host="0.0.0.0", port=5000)

def is_client_registered(username, password_hash):
    """Check if the client is registered."""
    with open(PASSWORD_FILE, 'r') as f:
        for line in f:
            if line.strip() == f"{username}:{password_hash}":
                return True
    return False

def log_activation(username):
    """Log client activation."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(ACTIVATION_LOG, 'a') as f:
        f.write(f"{timestamp},{username}\n")

def collect_stats():
    """Collect system stats from assigned nodes and format as CSV."""
    with open(CSV_FILE, 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Node", "Timestamp", "CPU(%)", "Memory(%)", "Processes"])
        with open(ASSIGNED_NODES_FILE, 'r') as nodes_file:
            for node in nodes_file:
                node = node.strip()
                if not node:
                    continue
                try:
                    cpu_mem = subprocess.check_output(["ssh", node, "ps -A -o %cpu,%mem | awk '{cpu+=$1; mem+=$2} END {print cpu, mem}'"]).decode().strip()
                    cpu_usage, memory_usage = cpu_mem.split()
                    process_count = subprocess.check_output(["ssh", node, "ps -A --no-headers | wc -l"]).decode().strip()
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    writer.writerow([node, timestamp, cpu_usage, memory_usage, process_count])
                except subprocess.CalledProcessError as e:
                    print(f"Error collecting stats from {node}: {e}")

def setup_ftp_on_node(node, username, password_hash):
    """Set up FTP on a job server."""
    try:
        # Install vsftpd if not already installed
        subprocess.run(["ssh", node, "sudo apt-get update && sudo apt-get install -y vsftpd"], check=True)
        # Configure vsftpd
        subprocess.run(["ssh", node, "echo -e 'anonymous_enable=NO\\nlocal_enable=YES\\nwrite_enable=YES\\nlocal_umask=022\\nchroot_local_user=YES\\nlisten=YES\\nlisten_ipv6=NO' | sudo tee /etc/vsftpd.conf"], check=True)
        # Restart vsftpd
        subprocess.run(["ssh", node, "sudo systemctl restart vsftpd"], check=True)
        # Create FTP user and set password
        subprocess.run(["ssh", node, f"sudo useradd -m -s /bin/bash {username}"], check=True)
        subprocess.run(["ssh", node, f"echo '{username}:{password_hash}' | sudo chpasswd -e"], check=True)
        # Allow FTP user to access a specific directory
        subprocess.run(["ssh", node, f"sudo usermod -d /home/{username} {username}"], check=True)
        print(f"FTP server set up on {node} for user {username}")
    except subprocess.CalledProcessError as e:
        print(f"Error setting up FTP on {node}: {e}")

def execute_interactive_command(command, time_limit):
    """Execute a command interactively with a time limit."""
    def target():
        subprocess.run(command, shell=True)

    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout=time_limit if time_limit != -1 else None)
    if thread.is_alive():
        subprocess.run(["pkill", "-f", command])
        print("Command terminated due to time limit.")

def submit_slurm_job(script_path, docker_repo, assigned_nodes):
    """Submit a job to SLURM and return the job ID."""
    try:
        sbatch_output = subprocess.check_output([
            "sbatch", "--job-name", f"Docker_Job", "--nodelist", assigned_nodes,
            "--wrap", f"srun docker run --rm -v {script_path}:/script.sh {docker_repo} bash /script.sh"
        ]).decode().strip()
        # Extract the job ID from the output (e.g., "Submitted batch job 12345")
        job_id = re.search(r"\d+", sbatch_output).group()
        return job_id
    except subprocess.CalledProcessError as e:
        print(f"Error submitting SLURM job: {e}")
        return None

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        headers = self.headers

        username = headers.get('X-Username', '').strip()
        password_hash = headers.get('X-Password-Hash', '').strip()
        docker_repo = headers.get('X-Docker-Repo', '').strip()
        node_count = headers.get('X-Node-Count', '').strip()
        time_limit = int(headers.get('X-Time-Limit', '-1').strip())

        if not is_client_registered(username, password_hash):
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Client not registered"}).encode())
            return

        log_activation(username)

        # Save the uploaded script to a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_script:
            temp_script.write(post_data)
            temp_script_path = temp_script.name

        print(f"Script saved to {temp_script_path}")

        script_success = False
        slurm_job_id = None
        if docker_repo and node_count:
            pull_success = True
            with open(ASSIGNED_NODES_FILE, 'r') as nodes_file:
                nodes = [line.strip() for line in nodes_file.readlines()[:int(node_count)]]
                for node in nodes:
                    try:
                        # Relay the script to the job server
                        subprocess.run(["scp", temp_script_path, f"{node}:/tmp/{os.path.basename(temp_script_path)}"], check=True)
                        # Pull Docker image on the job server
                        subprocess.run(["ssh", node, f"docker pull {docker_repo}"], check=True)
                        # Set up FTP on the job server
                        setup_ftp_on_node(node, username, password_hash)
                    except subprocess.CalledProcessError:
                        pull_success = False
                        break

            if pull_success:
                assigned_nodes = ",".join(nodes)
                slurm_job_id = submit_slurm_job(f"/tmp/{os.path.basename(temp_script_path)}", docker_repo, assigned_nodes)
                if slurm_job_id:
                    script_success = True
        else:
            with open(temp_script_path, 'r') as f:
                command = f.read().strip()
            execute_interactive_command(command, time_limit)
            script_success = True

        collect_stats()

        # Clean up the temporary script
        os.remove(temp_script_path)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "slurm_job_id": slurm_job_id,
            "script_success": script_success,
            "docker_repo": docker_repo,
            "node_count": node_count,
            "time_limit": time_limit,
            "system_stats": open(CSV_FILE, 'r').read(),
            "ftp_credentials": {
                "username": username,
                "password_hash": password_hash,
                "nodes": ",".join(nodes)
            }
        }).encode())

def run_server():
    httpd = HTTPServer(('0.0.0.0', PORT), RequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile=CERT_FILE, keyfile=KEY_FILE, server_side=True)
    print(f"Starting HTTPS server on port {PORT}...")
    httpd.serve_forever()

if __name__ == "__main__":
    # Start the Flask web interface in a separate thread
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    # Start the HTTPS server
    run_server()
