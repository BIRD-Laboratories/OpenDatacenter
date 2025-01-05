#!/bin/bash

# Configuration file
CONFIG_FILE="config.txt"

# Function to read configuration from file
read_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Error: Configuration file '$CONFIG_FILE' not found."
        exit 1
    fi

    # Read the configuration file
    while IFS='=' read -r key value; do
        case "$key" in
            CENTRAL_SERVER_IP) CENTRAL_SERVER_IP="$value" ;;
            ASSIGNED_NODES) IFS=',' read -r -a ASSIGNED_NODES <<< "$value" ;;
            WEB_DIR) WEB_DIR="$value" ;;
            PASSWORD_FILE) PASSWORD_FILE="$value" ;;
            CERT_FILE) CERT_FILE="$value" ;;
            KEY_FILE) KEY_FILE="$value" ;;
        esac
    done < "$CONFIG_FILE"
}

# Function to install dependencies on the central server
setup_central_server() {
    echo "Setting up the central server..."
    sudo apt-get update
    sudo apt-get install -y openssl nginx docker.io slurm-wlm

    # Generate SSL certificates
    echo "Generating SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 365 -nodes -subj "/CN=$CENTRAL_SERVER_IP"

    # Create web directory
    echo "Creating web directory..."
    sudo mkdir -p "$WEB_DIR"
    sudo chmod 755 "$WEB_DIR"

    # Configure Nginx
    echo "Configuring Nginx..."
    sudo bash -c "cat > /etc/nginx/sites-available/ftp <<EOF
server {
    listen 80;
    server_name $CENTRAL_SERVER_IP;

    root $WEB_DIR;
    index index.html;

    location / {
        auth_basic \"Restricted Access\";
        auth_basic_user_file /etc/nginx/.htpasswd;
        autoindex on;
    }
}
EOF"
    sudo ln -s /etc/nginx/sites-available/ftp /etc/nginx/sites-enabled/
    sudo systemctl reload nginx

    # Create password file
    echo "Creating password file..."
    sudo sh -c "echo -n 'username:' >> /etc/nginx/.htpasswd"
    sudo sh -c "openssl passwd -apr1 >> /etc/nginx/.htpasswd"

    echo "Central server setup complete."
}

# Function to install dependencies on assigned nodes
setup_assigned_nodes() {
    echo "Setting up assigned nodes..."
    for NODE in "${ASSIGNED_NODES[@]}"; do
        echo "Setting up node: $NODE"
        ssh "$NODE" "sudo apt-get update && sudo apt-get install -y vsftpd docker.io"
        ssh "$NODE" "sudo systemctl enable vsftpd && sudo systemctl start vsftpd"
        ssh "$NODE" "sudo ufw allow 21/tcp"
        echo "Node $NODE setup complete."
    done
}

# Function to start the HTTPS server
start_https_server() {
    echo "Starting HTTPS server..."
    ./job_manager.sh &
    echo "HTTPS server is running on port 8443."
}

# Main script
echo "Starting system setup..."
read_config
setup_central_server
setup_assigned_nodes
start_https_server
echo "System setup complete."
