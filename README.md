# OpenDatacenter

User Guide
**This guide is for users who want to interact with the server using the dashboard. It explains how to use the forms and understand the parameters.**

## 1. Accessing the Dashboard

Open your web browser and navigate to the dashboard URL (e.g., http://localhost:5001).
The dashboard will display several forms for interacting with the server.
## 2. Uploading a File

What is this?

Upload a file to the server. The file will be encrypted for security.

Steps:

Username: Enter your unique username.
Example: john_doe
Challenge: Enter the challenge code provided by the server.
Example: a1b2c3d4e5f6g7h8i9j0
Response: Enter the response code generated using your password and the challenge.
Example: 1a2b3c4d5e6f7g8h9i0j
Select File: Choose the file you want to upload.
Click Upload File.
The server will process your request and display a success or error message.
## 3. Submitting a Job

What is this?

Submit a job for the server to process. Jobs can include tasks like data processing or system commands.

Steps:

Username: Enter your unique username.
Example: john_doe
Challenge: Enter the challenge code provided by the server.
Example: a1b2c3d4e5f6g7h8i9j0
Response: Enter the response code generated using your password and the challenge.
Example: 1a2b3c4d5e6f7g8h9i0j
Job Data: Enter the data or instructions for the job.
Example: Process data from file X and save results to file Y.
Click Submit Job.
The server will process your request and display a success or error message.
4. Requesting a Key Change

What is this?

Request a new encryption key for your files. This ensures your files remain secure.

Steps:

Username: Enter your unique username.
Example: john_doe
Challenge: Enter the challenge code provided by the server.
Example: a1b2c3d4e5f6g7h8i9j0
Response: Enter the response code generated using your password and the challenge.
Example: 1a2b3c4d5e6f7g8h9i0j
Click Request Key Change.
The server will process your request and display a success or error message.
5. Viewing Real-Time Stats

What is this?

View live system statistics, such as CPU usage, memory usage, and the number of processes running.

Steps:

The Real-Time System Stats section automatically updates with live data.
The chart displays:
CPU (%): Percentage of CPU usage.
Memory (%): Percentage of memory usage.
Processes: Number of active processes.
Operator Guide

**This guide is for operators (technical administrators) who manage the server. It explains how to set up, configure, and troubleshoot the system.**

## 1. Setting Up the Server

Prerequisites:

Python 3.x installed.
Required Python libraries: Flask, cryptography, hashlib, hmac.
Steps:

Clone the repository or download the server code.
Install dependencies:
bash
Copy
pip install Flask cryptography
Generate SSL certificates (if not already generated):
bash
Copy
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
Start the server:
bash
Copy
python server.py
## 2. Managing Users

User Credentials:

User credentials are stored in the registered_clients.txt file.
Each line in the file follows the format:
Copy
username:salted_hash:salt:role
To add a new user:
Generate a salted hash of the user's password:
python
Copy
import hashlib, secrets
password = "user_password"
salt = secrets.token_bytes(16)
salted_password = salt + password.encode()
password_hash = hashlib.sha256(salted_password).hexdigest()
print(f"Username: user1, Salt: {salt.hex()}, Hash: {password_hash}")
Add the user to registered_clients.txt:
Copy
user1:password_hash:salt:client
## 3. Monitoring the Server

Logs:

Server logs are stored in /var/www/ftp/activation_log.txt.
Check the logs for errors or unusual activity.
Real-Time Stats:

Use the dashboard to monitor live system stats.
The stats are collected from the nodes listed in assigned_nodes.txt.
## 4. Troubleshooting

Common Issues:

400 Bad Request:
Ensure all required headers (X-Username, X-Challenge, X-Response) are included in the request.
Verify the challenge-response authentication.
File Upload Fails:
Check if the user's directory exists in /var/www/ftp/chroot.
Ensure the file permissions are correct.
Job Submission Fails:
Verify the job data format.
Check the server logs for errors.
Key Change Fails:
Ensure the user's files are accessible.
Verify the encryption key generation process.
## 5. Security Best Practices

Use HTTPS: Always run the server with SSL/TLS enabled.
Regular Backups: Backup the registered_clients.txt file and user directories regularly.
Monitor Logs: Regularly check server logs for suspicious activity.
Update Dependencies: Keep Python and libraries up to date.
## 6. Restarting the Server

To restart the server:
Stop the running server (Ctrl+C).
Start the server again:
bash
Copy
python server.py
## 7. Shutting Down the Server

To shut down the server:
Stop the running server (Ctrl+C).
Ensure all active connections are closed.
Important Note

The original codes for the server and dashboard will be sent to you via email. You must change the following before use:

SSL Certificates: Regenerate cert.pem and key.pem for your domain.
User Credentials: Replace the default credentials in registered_clients.txt with your own.
Configuration Parameters: Update variables like PORT, WEB_DIR, and UPLOAD_DIR to match your environment.
By following these guides, users can interact with the server securely, and operators can manage and maintain the system effectively.
