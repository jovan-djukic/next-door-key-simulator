#!/bin/bash
# Runs the plaintext Flask KME app and the PQC mTLS termination proxy as two
# processes in the same container. If either dies, the container exits so
# `restart: always` in docker-compose.yml can bring both back up cleanly.
set -e

python3 app.py &
FLASK_PID=$!

python3 pqc_tls_proxy.py &
PROXY_PID=$!

wait -n
echo "A KME process exited — stopping container."
kill "$FLASK_PID" "$PROXY_PID" 2>/dev/null || true
exit 1
