#!/bin/bash

PORT=${PORT:-5000} # Use the existing PORT environment variable, or default to 5000 if not set

set -m
# Variables to store process IDs
NC_PID=""

# Function to handle cleanup on Ctrl-C (SIGINT)
cleanup() {
    SIG=$1
    echo "Received signal $SIG, killing the children..."
    if [ ! -z "$NC_PID" ]; then
        SUB_PIDS=$(ps -o pid,pgid | awk -v pgid=$$ '$2==pgid' | awk '{print $1}')
        # pass the signal to all the subpids
        for pid in $SUB_PIDS; do
            if [ "$pid" != "$$" ]; then  # Skip killing the parent process again
                kill $SIG $pid 2>/dev/null
            fi
        done
        echo "killing $NC_PID"
        kill $SIG $NC_PID 2>/dev/null
    fi
    rm -f "$RESPONSE_FILE" 2>/dev/null
    exit 0
}

# Trap SIGINT (Ctrl-C) and run cleanup
trap 'cleanup TERM' TERM
trap 'cleanup INT' INT
trap 'cleanup HUP' HUP
trap 'cleanup QUIT' QUIT

echo "Bash Echo Server is running and listening on port $PORT..."

while true; do
    RESPONSE_FILE=$(mktemp)

    # Start nc in background and capture its PID
    nc -6 -l $PORT > "$RESPONSE_FILE" < <(

        while [ ! -s "$RESPONSE_FILE" ]; do
            sleep 0.1
        done
        REQUEST=$(cat "$RESPONSE_FILE")
        rm -f "$RESPONSE_FILE" 2>/dev/null

        # Format the response with both headers and body
        RESPONSE="${REQUEST}\n" # Add newline after request

        # Calculate the exact length of the response
        RESPONSE_LENGTH=$(echo -ne "$RESPONSE" | wc -c)

        # Send HTTP response with correct content length
        echo -ne "HTTP/1.1 200 OK\r\n"
        echo -ne "Content-Type: text/plain\r\n"
        echo -ne "Content-Length: $RESPONSE_LENGTH\r\n\r\n"
        echo -ne "$RESPONSE"
    ) &
    NC_PID=$!

    # Wait for both processes to complete
    wait $NC_PID
    wait $SUBSHELL_PID

    # Reset PIDs
    NC_PID=""
    SUBSHELL_PID=""


done
