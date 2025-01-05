from flask import Flask, render_template
import requests
import json
from datetime import datetime
import time

app = Flask(__name__)

# Server details
SERVER_URL = "https://localhost:8443"  # Replace with your server URL
CERT_FILE = "cert.pem"  # Path to the server's certificate for HTTPS

# Function to fetch system stats from the server
def fetch_system_stats():
    try:
        # Make a GET request to the server to fetch system stats
        response = requests.get(f"{SERVER_URL}/system_stats", verify=CERT_FILE)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to fetch stats: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching stats: {e}")
        return None

# Route to render the dashboard
@app.route("/")
def dashboard():
    # Fetch system stats from the server
    stats = fetch_system_stats()
    if stats:
        # Parse the stats into a format suitable for Chart.js
        nodes = []
        cpu_usage = []
        memory_usage = []
        timestamps = []
        for line in stats["system_stats"].split("\n"):
            if line:  # Skip empty lines
                node, timestamp, cpu, memory, _ = line.split(",")
                nodes.append(node)
                cpu_usage.append(float(cpu))
                memory_usage.append(float(memory))
                timestamps.append(timestamp)
        
        # Prepare data for the template
        data = {
            "nodes": nodes,
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "timestamps": timestamps,
        }
        return render_template("dashboard.html", data=data)
    else:
        return "Failed to fetch system stats from the server."

# Run the Flask app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
