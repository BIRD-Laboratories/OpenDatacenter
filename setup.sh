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
            WEB_DIR) WEB_DIR="$value" ;;
            PASSWORD_FILE) PASSWORD_FILE="$value" ;;
            CERT_FILE) CERT_FILE="$value" ;;
            KEY_FILE) KEY_FILE="$value" ;;
            CLIENT_USERS_FILE) CLIENT_USERS_FILE="$value" ;;
        esac
    done < "$CONFIG_FILE"
}

# Function to discover node IPs on the local network
discover_node_ips() {
    echo "Discovering node IPs on the local network..."
    local network_range="192.168.1.0/24"  # Adjust this to match your network range
    ASSIGNED_NODES=($(nmap -sn $network_range | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -v "$CENTRAL_SERVER_IP"))
    echo "Discovered nodes: ${ASSIGNED_NODES[@]}"
}

# Function to create client users from a text file
create_client_users() {
    echo "Creating client users from file: $CLIENT_USERS_FILE..."
    if [[ ! -f "$CLIENT_USERS_FILE" ]]; then
        echo "Error: Client users file '$CLIENT_USERS_FILE' not found."
        exit 1
    fi

    while IFS= read -r user; do
        # Skip empty lines
        if [[ -z "$user" ]]; then
            continue
        fi

        # Create the user with no login shell
        if id "$user" &>/dev/null; then
            echo "User '$user' already exists. Skipping."
        else
            sudo useradd -m -s /usr/sbin/nologin "$user"
            echo "User '$user' created."
        fi
    done < "$CLIENT_USERS_FILE"
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

    # Set ownership of the web directory to root
    sudo chown root:root "$WEB_DIR"
    sudo chmod 700 "$WEB_DIR"  # Only root can read/write/execute

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

    # Create password file for Nginx basic auth
    echo "Creating password file for Nginx..."
    sudo touch /etc/nginx/.htpasswd
    sudo chown root:root /etc/nginx/.htpasswd
    sudo chmod 600 /etc/nginx/.htpasswd  # Only root can read/write

    # Add client users to the password file
    while IFS= read -r user; do
        # Skip empty lines
        if [[ -z "$user" ]]; then
            continue
        fi

        echo "Adding user '$user' to Nginx password file..."
        sudo sh -c "echo -n '$user:' >> /etc/nginx/.htpasswd"
        sudo sh -c "openssl passwd -apr1 >> /etc/nginx/.htpasswd"
    done < "$CLIENT_USERS_FILE"

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

# Function to start the job manager (Python program)
start_job_manager() {
    echo "Starting job manager..."
    python3 server.py &
    echo "Job manager is running."
}

# Main script
echo "Starting system setup..."
read_config
discover_node_ips
create_client_users
setup_central_server
setup_assigned_nodes
start_job_manager
echo "System setup complete."
