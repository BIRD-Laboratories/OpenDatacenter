import os
import subprocess
import hashlib
import secrets
import time
from flask import Flask, jsonify, request, send_file
from cryptography.fernet import Fernet

app = Flask(__name__)

# Configuration
USER_DIR = "users"
QEMU_DIR = "qemu_images"
UPLOAD_DIR = "uploads"
PASSWORD_FILE = "passwords.txt"
ACTIVITY_DIR = "instance_logs"

os.makedirs(ACTIVITY_DIR, exist_ok=True)

def derive_key(password, salt):
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32
    )

def user_instance(username, port):
    local_app = Flask(username)
    
    @local_app.route("/")
    def user_home():
        return jsonify({"status": "active", "user": username})
    
    local_app.run(port=port, threaded=True)

@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    
    # Generate user-specific encryption key
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    
    # Store credentials
    with open(PASSWORD_FILE, "a") as f:
        f.write(f"{username}:{salt.hex()}:{hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()}\n")
    
    # Create user environment
    user_path = os.path.join(USER_DIR, username)
    os.makedirs(user_path, exist_ok=True)
    os.chmod(user_path, 0o700)
    
    # Create QEMU image
    subprocess.run([
        "qemu-img", "create", "-f", "qcow2",
        "-b", f"{QEMU_DIR}/base.img",
        f"{QEMU_DIR}/{username}.img"
    ])
    
    return jsonify({"message": "User created"}), 201

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if parts[0] == username:
                salt = bytes.fromhex(parts[1])
                stored_hash = bytes.fromhex(parts[2])
                break
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    
    test_hash = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1
    )
    
    if not secrets.compare_digest(test_hash, stored_hash):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Update activity log
    open(f"{ACTIVITY_DIR}/{username}_activity.log", "w").close()
    return jsonify({
        "message": "Login successful",
        "encryption_key": Fernet(Fernet.generate_key()).encrypt(derive_key(password, salt)).decode()
    }), 200

@app.route("/upload", methods=["POST"])
def upload():
    username = request.headers.get("X-User")
    enc_key = request.headers.get("X-Key")
    
    if not username or not enc_key:
        return jsonify({"error": "Missing credentials"}), 401
    
    # Verify activity
    open(f"{ACTIVITY_DIR}/{username}_activity.log", "w").close()
    
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file provided"}), 400
    
    # User-specific encryption
    user_key = Fernet(enc_key.encode())
    user_dir = os.path.join(USER_DIR, username)
    file_path = os.path.join(user_dir, file.filename)
    
    file.save(file_path)
    with open(file_path, "rb") as f:
        encrypted = user_key.encrypt(f.read())
    
    with open(file_path, "wb") as f:
        f.write(encrypted)
    
    return jsonify({"message": "File encrypted and stored"}), 200

@app.route("/execute", methods=["POST"])
def execute():
    username = request.headers.get("X-User")
    enc_key = request.headers.get("X-Key")
    
    if not username or not enc_key:
        return jsonify({"error": "Missing credentials"}), 401
    
    # Verify activity
    open(f"{ACTIVITY_DIR}/{username}_activity.log", "w").close()
    
    script = request.files.get("script")
    if not script:
        return jsonify({"error": "No script provided"}), 400
    
    # Decrypt and execute
    user_key = Fernet(enc_key.encode())
    decrypted_script = user_key.decrypt(script.read())
    
    # Sandboxed execution
    try:
        result = subprocess.run(
            ["qemu-system-x86_64", "-snapshot", "-drive", f"file={QEMU_DIR}/{username}.img,format=qcow2"],
            input=decrypted_script,
            capture_output=True,
            timeout=30
        )
        return jsonify({
            "output": result.stdout.decode(),
            "error": result.stderr.decode()
        }), 200
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Execution timed out"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"))
