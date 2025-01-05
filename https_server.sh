#!/bin/bash

# Variables
PORT=8443
CERT_FILE="cert.pem"
KEY_FILE="key.pem"
OUTPUT_SCRIPT="received_script.sh"
CSV_FILE="/var/www/ftp/system_stats.csv"  # Save CSV to the web-accessible directory
PASSWORD_FILE="registered_clients.txt"    # File containing registered password hashes (format: username:password_hash)
ACTIVATION_LOG="/var/www/ftp/activation_log.txt"  # Log file in the web-accessible directory
ASSIGNED_NODES_FILE="assigned_nodes.txt"  # File containing assigned node IPs
WEB_DIR="/var/www/ftp"                    # Web-accessible directory

# Ensure the web directory exists
mkdir -p "$WEB_DIR"
chmod 755 "$WEB_DIR"

# Function to check if the client is registered
is_client_registered() {
    local USERNAME="$1"
    local PASSWORD_HASH="$2"
    if grep -q "^$USERNAME:$PASSWORD_HASH$" "$PASSWORD_FILE"; then
        return 0  # Client is registered
    else
        return 1  # Client is not registered
    fi
}

# Function to log client activation
log_activation() {
    local USERNAME="$1"
    local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$TIMESTAMP,$USERNAME" >> "$ACTIVATION_LOG"
}

# Function to collect system stats from assigned nodes and format as CSV
collect_stats() {
    echo "Node,Timestamp,CPU(%),Memory(%),Processes" > "$CSV_FILE"
    while read -r NODE; do
        # Collect stats from each assigned node using SSH
        ssh "$NODE" "ps -A -o %cpu,%mem | awk '{cpu+=\$1; mem+=\$2} END {print cpu, mem}'" | while read -r CPU_USAGE MEMORY_USAGE; do
            PROCESS_COUNT=$(ssh "$NODE" "ps -A --no-headers | wc -l")
            TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
            echo "$NODE,$TIMESTAMP,$CPU_USAGE,$MEMORY_USAGE,$PROCESS_COUNT" >> "$CSV_FILE"
        done
    done < "$ASSIGNED_NODES_FILE"
}

# Function to set up FTP on a node
setup_ftp_on_node() {
    local NODE="$1"
    local USERNAME="$2"
    local PASSWORD_HASH="$3"
    # Install vsftpd (FTP server) on the node
    ssh "$NODE" "sudo apt-get update && sudo apt-get install -y vsftpd"
    # Configure vsftpd
    ssh "$NODE" "echo -e 'anonymous_enable=NO\\nlocal_enable=YES\\nwrite_enable=YES\\nlocal_umask=022\\nchroot_local_user=YES\\nlisten=YES\\nlisten_ipv6=NO' | sudo tee /etc/vsftpd.conf"
    # Restart vsftpd
    ssh "$NODE" "sudo systemctl restart vsftpd"
    # Create FTP user and set password
    ssh "$NODE" "sudo useradd -m -s /bin/bash $USERNAME"
    ssh "$NODE" "echo '$USERNAME:$PASSWORD_HASH' | sudo chpasswd -e"
    # Allow FTP user to access the entire file system (or a specific directory)
    ssh "$NODE" "sudo usermod -d / $USERNAME"
    echo "FTP server set up on $NODE for user $USERNAME"
}

# Function to handle the client connection
handle_client() {
    # Read the HTTP request headers
    USERNAME=""
    PASSWORD_HASH=""
    SLURM_JOB_ID=""
    DOCKER_REPO=""
    NODE_COUNT=""
    while read -r line; do
        echo "$line"
        # Extract username and password hash from headers
        if [[ "$line" =~ ^X-Username:[[:space:]]*(.*) ]]; then
            USERNAME="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ ^X-Password-Hash:[[:space:]]*(.*) ]]; then
            PASSWORD_HASH="${BASH_REMATCH[1]}"
        fi
        # Extract SLURM job ID from headers (if provided)
        if [[ "$line" =~ ^X-Slurm-Job-ID:[[:space:]]*(.*) ]]; then
            SLURM_JOB_ID="${BASH_REMATCH[1]}"
        fi
        # Extract Docker repository from headers (if provided)
        if [[ "$line" =~ ^X-Docker-Repo:[[:space:]]*(.*) ]]; then
            DOCKER_REPO="${BASH_REMATCH[1]}"
        fi
        # Extract node count from headers (if provided)
        if [[ "$line" =~ ^X-Node-Count:[[:space:]]*(.*) ]]; then
            NODE_COUNT="${BASH_REMATCH[1]}"
        fi
        # End of headers
        if [[ "$line" == $'\r' ]]; then
            break
        fi
    done

    # Check if the client is registered
    if ! is_client_registered "$USERNAME" "$PASSWORD_HASH"; then
        echo "HTTP/1.1 403 Forbidden"
        echo "Content-Type: application/json"
        echo "Connection: close"
        echo
        echo "{\"error\": \"Client not registered\"}"
        return
    fi

    # Log the client activation
    log_activation "$USERNAME"

    # Read the body of the request (the bash script)
    echo "Receiving script..."
    cat > "$OUTPUT_SCRIPT"

    # Log the received parameters
    echo "SLURM Job ID: $SLURM_JOB_ID"
    echo "Docker Repository: $DOCKER_REPO"
    echo "Node Count: $NODE_COUNT"
    echo "Script saved to $OUTPUT_SCRIPT"

    # Check if SLURM job already exists
    SLURM_JOB_EXISTS="false"
    if [[ -n "$SLURM_JOB_ID" ]]; then
        if squeue -j "$SLURM_JOB_ID" &> /dev/null; then
            SLURM_JOB_EXISTS="true"
        fi
    fi

    # Process the script with the provided parameters
    SCRIPT_SUCCESS="false"
    if [[ -n "$SLURM_JOB_ID" && -n "$DOCKER_REPO" && -n "$NODE_COUNT" ]]; then
        echo "Processing script with SLURM Job ID $SLURM_JOB_ID, Docker repository $DOCKER_REPO, and $NODE_COUNT nodes..."
        # Pull the Docker image on all assigned nodes
        PULL_SUCCESS="true"
        while read -r NODE; do
            ssh "$NODE" "docker pull $DOCKER_REPO" || PULL_SUCCESS="false"
            # Set up FTP on the assigned node
            setup_ftp_on_node "$NODE" "$USERNAME" "$PASSWORD_HASH"
        done < "$ASSIGNED_NODES_FILE"
        if [[ "$PULL_SUCCESS" == "true" ]]; then
            # Submit the script to SLURM, routing it to the specified number of nodes
            ASSIGNED_NODES=$(head -n "$NODE_COUNT" "$ASSIGNED_NODES_FILE" | paste -sd,)
            SBATCH_OUTPUT=$(sbatch --job-name="Docker_Job_$SLURM_JOB_ID" --nodelist="$ASSIGNED_NODES" --wrap="srun docker run --rm $DOCKER_REPO bash $OUTPUT_SCRIPT" 2>&1)
            if [[ $? -eq 0 ]]; then
                SCRIPT_SUCCESS="true"
            fi
        fi
    fi

    # Collect system stats from assigned nodes as CSV
    collect_stats

    # Remove the sent script from the system
    rm -f "$OUTPUT_SCRIPT"

    # Send a JSON response back to the client
    echo "HTTP/1.1 200 OK"
    echo "Content-Type: application/json"
    echo "Connection: close"
    echo
    echo "{
        \"slurm_job_exists\": $SLURM_JOB_EXISTS,
        \"script_success\": $SCRIPT_SUCCESS,
        \"slurm_job_id\": \"$SLURM_JOB_ID\",
        \"docker_repo\": \"$DOCKER_REPO\",
        \"node_count\": $NODE_COUNT,
        \"system_stats\": \"$(awk '{printf "%s\\n", $0}' < "$CSV_FILE")\",
        \"ftp_credentials\": {
            \"username\": \"$USERNAME\",
            \"password_hash\": \"$PASSWORD_HASH\",
            \"nodes\": \"$(paste -sd, < "$ASSIGNED_NODES_FILE")\"
        }
    }"
}

# Start the HTTPS server and continuously listen for connections
echo "Starting HTTPS server on port $PORT..."
while true; do
    openssl s_server -accept $PORT -cert "$CERT_FILE" -key "$KEY_FILE" -www -quiet | while read -r line; do
        handle_client
    done
done
