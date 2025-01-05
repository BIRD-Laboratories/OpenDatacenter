from flask import Flask, request, jsonify
import subprocess
from threading import Thread
import time

app = Flask(__name__)

# Endpoint to execute a command and return output
@app.route("/execute", methods=["POST"])
def execute_command():
    data = request.json
    command = data.get("command")
    if not command:
        return jsonify({"error": "No command provided"}), 400

    try:
        # Execute the command
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint to stream command output in real-time
@app.route("/stream", methods=["POST"])
def stream_command():
    data = request.json
    command = data.get("command")
    if not command:
        return jsonify({"error": "No command provided"}), 400

    def generate():
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout:
            yield f"data: {line}\n\n"
        for line in process.stderr:
            yield f"data: {line}\n\n"

    return app.response_class(generate(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
