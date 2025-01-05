import os
import subprocess
import threading
import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
from flask import Flask, render_template, jsonify, request, Response, send_file
import hashlib
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
from collections import deque

# Variables
PORT = 8443
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
PASSWORD_FILE = "registered_clients.txt"  # File containing registered client credentials (format: username:salted_hash:salt:role)
ACTIVATION_LOG = "/var/www/ftp/activation_log.txt"  # Log file in the web-accessible directory
ASSIGNED_NODES_FILE = "assigned_nodes.txt"  # File containing assigned node IPs
WEB_DIR = "/var/www/ftp"  # Web-accessible directory
UPLOAD_DIR = "/var/www/ftp/uploads"  # Directory for uploaded files
CHROOT_BASE = "/var/www/ftp/chroot"  # Base directory for chroot environments
JOBS_FILE = "jobs.txt"  # File to store job submissions

# Ensure the web directory exists
os.makedirs(WEB_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CHROOT_BASE, exist_ok=True)
os.chmod(WEB_DIR, 0o755)
os.chmod(UPLOAD_DIR, 0o755)
os.chmod(CHROOT_BASE, 0o755)

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

# Job queue and status tracking
jobs = deque()
job_status = {}

# Helper function to hash passwords with a salt
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate a random salt
    salted_password = salt + password.encode()
    return hashlib.sha256(salted_password).hexdigest(), salt

# Helper function to verify a challenge-response
def verify_challenge_response(username, challenge, response):
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 4 and parts[0] == username:
                stored_hash = parts[1]
                salt = bytes.fromhex(parts[2])
                break
        else:
            return False  # User not found

    # Recompute the expected response
    expected_response = hmac.new(salt + stored_hash.encode(), challenge, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_response, response)

# Helper function to create a chroot environment for the user
def create_chroot_environment(username):
    user_chroot_dir = os.path.join(CHROOT_BASE, username)
    os.makedirs(user_chroot_dir, exist_ok=True)

    # Create minimal directories and copy required binaries
    for dir_name in ["bin", "lib", "lib64", "usr", "etc"]:
        os.makedirs(os.path.join(user_chroot_dir, dir_name), exist_ok=True)

    # Copy required binaries and libraries
    binaries = ["/bin/bash", "/bin/ls", "/bin/python3"]
    for binary in binaries:
        subprocess.run(["cp", binary, os.path.join(user_chroot_dir, "bin")], check=True)
        for line in subprocess.run(["ldd", binary], stdout=subprocess.PIPE, text=True).stdout.splitlines():
            if "=>" in line:
                lib_path = line.split()[2]
                lib_dir = os.path.dirname(lib_path)
                os.makedirs(os.path.join(user_chroot_dir, lib_dir), exist_ok=True)
                subprocess.run(["cp", lib_path, os.path.join(user_chroot_dir, lib_dir)], check=True)

    # Set permissions
    os.chmod(user_chroot_dir, 0o755)

# Helper function to derive a symmetric key from a password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

# Helper function to encrypt a file using a symmetric key
def encrypt_file(file_path, key):
    cipher_suite = Fernet(Fernet(key))
    with open(file_path, "rb") as f:
        file_data = f.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    with open(file_path, "wb") as f:
        f.write(encrypted_data)

# Helper function to decrypt a file using a symmetric key
def decrypt_file(file_path, key):
    cipher_suite = Fernet(Fernet(key))
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    with open(file_path, "wb") as f:
        f.write(decrypted_data)

# Helper function to collect live system stats
def collect_live_stats():
    stats_data = []
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

                # Append stats to the list
                stats_data.append({
                    "Node": node,
                    "Timestamp": timestamp,
                    "CPU(%)": cpu_usage,
                    "Memory(%)": memory_usage,
                    "Processes": process_count
                })
            except subprocess.CalledProcessError as e:
                print(f"Error collecting stats from {node}: {e}")
    return stats_data

@app.route("/")
def dashboard():
    """Render the dashboard with server stats."""
    return render_template("dashboard.html")

@app.route("/register", methods=["POST"])
def register():
    """Register a new user."""
    username = request.json.get("username", "").strip()
    password = request.json.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Hash the password with a salt
    password_hash, salt = hash_password(password)

    # Save the user's credentials
    with open(PASSWORD_FILE, "a") as f:
        f.write(f"{username}:{password_hash}:{salt.hex()}:client\n")

    return jsonify({"message": "User registered successfully"}), 200

@app.route("/get_challenge", methods=["GET"])
def get_challenge():
    """Generate a challenge for the user."""
    username = request.headers.get("X-Username", "").strip()

    if not username:
        return jsonify({"error": "Username is required"}), 400

    # Generate a random challenge
    challenge = secrets.token_bytes(16)
    return jsonify({"challenge": challenge.hex()}), 200

@app.route("/request_key_change", methods=["POST"])
def request_key_change():
    """Handle a request to change the decryption key."""
    username = request.headers.get("X-Username", "").strip()
    challenge = request.headers.get("X-Challenge", "").strip()
    response = request.headers.get("X-Response", "").strip()

    if not username or not challenge or not response:
        return jsonify({"error": "Missing credentials"}), 400

    # Verify the challenge-response
    if not verify_challenge_response(username, bytes.fromhex(challenge), response):
        return jsonify({"error": "Authentication failed"}), 403

    # Generate a new encryption key
    new_key = Fernet.generate_key()

    # Re-encrypt the user's files with the new key
    user_dir = os.path.join(CHROOT_BASE, username)
    for root, _, files in os.walk(user_dir):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
            cipher_suite = Fernet(new_key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open(file_path, "wb") as f:
                f.write(decrypted_data)

    return jsonify({"message": "Key change successful", "new_key": new_key.decode()}), 200

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file uploads (restricted to clients)."""
    username = request.headers.get("X-Username", "").strip()
    challenge = request.headers.get("X-Challenge", "").strip()
    response = request.headers.get("X-Response", "").strip()

    if not username or not challenge or not response:
        return jsonify({"error": "Missing credentials"}), 400

    # Verify the challenge-response
    if not verify_challenge_response(username, bytes.fromhex(challenge), response):
        return jsonify({"error": "Authentication failed"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    # Create a chroot environment for the user if it doesn't exist
    create_chroot_environment(username)

    # Save the file to the user's chroot directory
    user_chroot_dir = os.path.join(CHROOT_BASE, username)
    file_path = os.path.join(user_chroot_dir, file.filename)
    file.save(file_path)

    # Encrypt the file using the user's password hash as the key
    key = derive_key(request.headers.get("X-Response", ""), secrets.token_bytes(16))
    encrypt_file(file_path, key)

    return jsonify({"message": "File uploaded and encrypted successfully", "file_path": file_path}), 200

@app.route("/submit_job", methods=["POST"])
def submit_job():
    """Submit a job for processing."""
    username = request.headers.get("X-Username", "").strip()
    challenge = request.headers.get("X-Challenge", "").strip()
    response = request.headers.get("X-Response", "").strip()

    if not username or not challenge or not response:
        return jsonify({"error": "Missing credentials"}), 400

    # Verify the challenge-response
    if not verify_challenge_response(username, bytes.fromhex(challenge), response):
        return jsonify({"error": "Authentication failed"}), 403

    job_data = request.json.get("job_data", "")
    if not job_data:
        return jsonify({"error": "Job data is required"}), 400

    # Add the job to the queue
    job_id = len(jobs) + 1
    jobs.append({"job_id": job_id, "username": username, "job_data": job_data})
    job_status[job_id] = "pending"

    return jsonify({"message": "Job submitted successfully", "job_id": job_id}), 200

@app.route("/job_status/<int:job_id>", methods=["GET"])
def get_job_status(job_id):
    """Get the status of a job."""
    username = request.headers.get("X-Username", "").strip()
    challenge = request.headers.get("X-Challenge", "").strip()
    response = request.headers.get("X-Response", "").strip()

    if not username or not challenge or not response:
        return jsonify({"error": "Missing credentials"}), 400

    # Verify the challenge-response
    if not verify_challenge_response(username, bytes.fromhex(challenge), response):
        return jsonify({"error": "Authentication failed"}), 403

    if job_id not in job_status:
        return jsonify({"error": "Job not found"}), 404

    return jsonify({"job_id": job_id, "status": job_status[job_id]}), 200

@app.route("/stats")
def stats():
    """Serve system stats in JSON format (restricted to clients)."""
    username = request.headers.get('X-Username', '').strip()
    challenge = request.headers.get('X-Challenge', '').strip()
    response = request.headers.get('X-Response', '').strip()

    if not username or not challenge or not response:
        return jsonify({"error": "Missing credentials"}), 400

    # Verify the challenge-response
    if not verify_challenge_response(username, bytes.fromhex(challenge), response):
        return jsonify({"error": "Unauthorized access"}), 403

    try:
        stats_data = collect_live_stats()
        return jsonify(stats_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stream_stats")
def stream_stats():
    """Stream live system stats (restricted to clients)."""
    username = request.headers.get('X-Username', '').strip()
    challenge = request.headers.get('X-Challenge', '').strip()
    response = request.headers.get('X-Response', '').strip()

    if not username or not challenge or not response:
        return jsonify({"error": "Missing credentials"}), 400

    # Verify the challenge-response
    if not verify_challenge_response(username, bytes.fromhex(challenge), response):
        return jsonify({"error": "Unauthorized access"}), 403

    def generate():
        while True:
            stats_data = collect_live_stats()
            yield f"data: {json.dumps(stats_data)}\n\n"
            time.sleep(10)  # Update stats every 10 seconds

    return Response(generate(), content_type='text/event-stream')

def run_flask_app():
    """Run the Flask web interface on a different port."""
    app.run(host="0.0.0.0", port=5001)

def run_server():
    httpd = HTTPServer(('0.0.0.0', PORT), BaseHTTPRequestHandler)

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
