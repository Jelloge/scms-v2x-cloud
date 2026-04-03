#!/bin/bash
#
# run_multi.sh - launch N concurrent rtos_client instances for load testing
#
# usage: bash scripts/run_multi.sh <EJBCA_IP> <NUM_CLIENTS> [DURATION_SEC] [PROVISION_PERIOD]
# e.g.:  bash scripts/run_multi.sh 18.118.3.99 5 180 5
#
# each client gets:
#   - its own cert_store_<id>/ directory
#   - its own EJBCA username: qnx-vehicle-<id>
#   - its own metrics.csv
#
# IMPORTANT: you must create matching EJBCA end entities first:
#   qnx-vehicle-1, qnx-vehicle-2, ..., qnx-vehicle-N
#   all with password "steed", same cert profile and EE profile

set -e

EJBCA_IP="$1"
NUM_CLIENTS="${2:-3}"
DURATION="${3:-180}"
PROVISION_PERIOD="${4:-5}"
BINARY="./rtos_client"

if [ -z "$EJBCA_IP" ]; then
    echo "usage: $0 <EJBCA_IP> [NUM_CLIENTS] [DURATION_SEC] [PROVISION_PERIOD]"
    echo ""
    echo "example: $0 18.118.3.99 5 180 5"
    echo "  -> launches 5 clients for 180 seconds, provisioning every 5s"
    echo ""
    echo "prerequisites:"
    echo "  - EJBCA end entities qnx-vehicle-1 through qnx-vehicle-N must exist"
    echo "  - SuperAdmin certs in ./cert_store/"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "ERROR: $BINARY not found. Run 'make' first."
    exit 1
fi

echo "================================================================"
echo " Multi-Client Load Test"
echo "================================================================"
echo " EJBCA:      $EJBCA_IP"
echo " Clients:    $NUM_CLIENTS"
echo " Duration:   ${DURATION}s"
echo " Provision:  every ${PROVISION_PERIOD}s"
echo "================================================================"
echo ""

PIDS=()

# launch all clients
for i in $(seq 1 "$NUM_CLIENTS"); do
    mkdir -p "cert_store_${i}"
    echo "[launch] Starting client $i (qnx-vehicle-$i)..."
    $BINARY "$EJBCA_IP" "$PROVISION_PERIOD" "$i" > "cert_store_${i}/stdout.log" 2>&1 &
    PIDS+=($!)
    # stagger launches slightly to avoid EJBCA thundering herd
    sleep 1
done

echo ""
echo "[info] All $NUM_CLIENTS clients running. PIDs: ${PIDS[*]}"
echo "[info] Waiting ${DURATION}s..."
echo ""

sleep "$DURATION"

echo "[stop] Sending SIGINT to all clients..."
for pid in "${PIDS[@]}"; do
    kill -INT "$pid" 2>/dev/null || true
done

# wait for graceful shutdown (up to 10s)
for pid in "${PIDS[@]}"; do
    timeout 10 tail --pid="$pid" -f /dev/null 2>/dev/null || true
done

sleep 2

echo ""
echo "================================================================"
echo " Results"
echo "================================================================"

for i in $(seq 1 "$NUM_CLIENTS"); do
    CSV="cert_store_${i}/metrics.csv"
    if [ -f "$CSV" ]; then
        LINES=$(wc -l < "$CSV")
        echo " Client $i: $CSV ($((LINES - 1)) data points)"
    else
        echo " Client $i: NO DATA (csv not found)"
    fi
done

echo ""
echo "Done. CSV files are in cert_store_1/ through cert_store_${NUM_CLIENTS}/"
echo "To analyze: python3 src/analysis_script.py  (update paths as needed)"
