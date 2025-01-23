#!/bin/bash
# Admin password verification
read -sp "Enter admin password: " password
echo
if [ "$password" != "secureadmin123" ]; then
    echo "Invalid admin password"
    exit 1
fi

# Start main instance and monitoring
python3 app.py &

# Process manager
while true; do
    # Spawn new instances for active users
    for user_dir in users/*; do
        user=$(basename $user_dir)
        logfile="instance_logs/${user}_activity.log"
        
        if [ ! -f "$logfile" ]; then
            port=$(( 8000 + $(ls instance_logs | wc -l) ))
            python3 -c "from app import user_instance; user_instance('$user', $port)" &
            echo $! > "instance_logs/${user}.pid"
            touch "$logfile"
        fi
    done

    # Cleanup inactive instances (15 minutes)
    find instance_logs -name '*.log' -mmin +15 -exec bash -c '
        user=$(basename {} "_activity.log")
        kill $(cat "instance_logs/${user}.pid") 2>/dev/null
        rm "instance_logs/${user}.pid" "instance_logs/${user}_activity.log"
    ' \;

    sleep 60
done
