import os
import subprocess
import threading
import time
import json
import csv
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import tempfile
import re
from flask import Flask, render_template, jsonify, request, Response, send_file, abort
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
UPLOAD_DIR = "/var/www/ftp/uploads"         # Directory for uploaded files

# Ensure the web directory exists
os.makedirs(WEB_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.chmod(WEB_DIR, 0o755)
os.chmod(UPLOAD_DIR, 0o755)

# Generate SSL certificates if they don't exist
if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
    print("Generating SSL certificates...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", KEY_FILE, "-out", CERT_FILE,
        "-days", "365", "-nodes", "-subj", "/CN=localhost"
    ], check=True)
    print(f"SSL certificates generated: {CERT_FILE}, {KEY_FILE}")

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

@app.route("/stats")
def stats():
    """Serve system stats in JSON format."""
    try:
        stats_df = pd.read_csv(CSV_FILE)
        return jsonify(stats_df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/nodes")
def nodes():
    """Serve the list of nodes in JSON format."""
    try:
        with open(ASSIGNED_NODES_FILE, 'r') as f:
            nodes = [line.strip() for line in f if line.strip()]
        return jsonify({"nodes": nodes})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stream", methods=["POST"])
def stream():
    """Execute a command and stream the output."""
    data = request.json
    command = data.get("command")
    node = data.get("node")

    def generate():
        if node:
            ssh_command = f"ssh {node} {command}"
        else:
            ssh_command = command

        process = subprocess.Popen(ssh_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for line in process.stdout:
            yield line
        for line in process.stderr:
            yield line

    return Response(generate(), content_type='text/plain')

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file uploads."""
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    # Save the file to the upload directory
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(file_path)
    return jsonify({"message": "File uploaded successfully", "file_path": file_path}), 200

@app.route("/download")
def download_file():
    """Serve a file for download."""
    try:
        # Get the file path from the query parameter
        file_path = request.args.get("file_path")
        if not file_path:
            return jsonify({"error": "File path is required"}), 400

        # Validate the file path
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        # Send the file for download
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_flask_app():
    """Run the Flask web interface on a different port."""
    app.run(host="0.0.0.0", port=5001)  # Changed to port 5001

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
                    # Collect CPU and memory usage
                    cpu_mem = subprocess.check_output(
                        ["ssh", node, "ps -A -o %cpu,%mem | awk '{cpu+=$1; mem+=$2} END {print cpu, mem}'"]
                    ).decode().strip()
                    cpu_usage, memory_usage = cpu_mem.split()

                    # Collect process count
                    process_count = subprocess.check_output(
                        ["ssh", node, "ps -A --no-headers | wc -l"]
                    ).decode().strip()

                    # Get current timestamp
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

                    # Write stats to CSV
                    writer.writerow([node, timestamp, cpu_usage, memory_usage, process_count])
                except subprocess.CalledProcessError as e:
                    print(f"Error collecting stats from {node}: {e}")

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
        nodes = []
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
        }).encode())

def run_server():
    httpd = HTTPServer(('0.0.0.0', PORT), RequestHandler)

    # Create an SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # Wrap the socket with SSL
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Starting HTTPS server on port {PORT}...")
    httpd.serve_forever()

if __name__ == "__main__":
    # Start the Flask web interface in a separate thread
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    # Start the HTTPS server
    run_server()
