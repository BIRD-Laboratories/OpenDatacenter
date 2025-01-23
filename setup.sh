#!/bin/bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y python3-pip qemu-kvm libvirt-clients libvirt-daemon-system bridge-utils
pip3 install flask cryptography

# Generate SSL certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

# Create secure directories
mkdir -p {users,qemu_images,uploads,instance_logs}
chmod 700 {users,qemu_images,uploads,instance_logs}

# Create password database
touch passwords.txt
chmod 600 passwords.txt
