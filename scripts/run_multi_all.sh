#!/bin/bash
#
# run_multi_all.sh — Run 3, 5, and 10 client tests sequentially
# Results go into new_multi_results/{3,5,10}_clients/client_N.csv
#
set -e

EJBCA_IP="18.118.3.99"
DURATION=180
PROVISION_PERIOD=5
BINARY="./rtos_client"
OUTDIR="./new_multi_results"

cd "$(dirname "$0")/.."

echo "================================================================"
echo " SCMS Multi-Client Full Test Suite"
echo " EJBCA: $EJBCA_IP | Duration: ${DURATION}s | Provision: ${PROVISION_PERIOD}s"
echo "================================================================"

run_test() {
    NUM=$1
    echo ""
    echo "============================================================"
    echo " TEST: $NUM concurrent clients"
    echo "============================================================"

    # Clean up any old cert stores for this run
    for i in $(seq 1 "$NUM"); do
        rm -rf "cert_store_${i}"
        mkdir -p "cert_store_${i}"
        # Copy superadmin certs so each client can authenticate
        cp cert_store/superadmin_cert.pem "cert_store_${i}/"
        cp cert_store/superadmin_key.pem "cert_store_${i}/"
        cp cert_store/SCMSRootCA.pem "cert_store_${i}/" 2>/dev/null || true
    done

    PIDS=()

    for i in $(seq 1 "$NUM"); do
        echo "[launch] Starting client $i (qnx-vehicle-$i)..."
        $BINARY "$EJBCA_IP" "$PROVISION_PERIOD" "$i" > "cert_store_${i}/stdout.log" 2>&1 &
        PIDS+=($!)
        sleep 1  # stagger to avoid thundering herd
    done

    echo "[info] All $NUM clients running. PIDs: ${PIDS[*]}"
    echo "[info] Waiting ${DURATION}s..."

    sleep "$DURATION"

    echo "[stop] Sending SIGINT to all clients..."
    for pid in "${PIDS[@]}"; do
        kill -INT "$pid" 2>/dev/null || true
    done

    # Wait for graceful shutdown
    sleep 5

    # Kill any stragglers
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done

    sleep 2

    # Collect results
    echo "[collect] Copying results..."
    DEST="${OUTDIR}/${NUM}_clients"
    mkdir -p "$DEST"

    for i in $(seq 1 "$NUM"); do
        CSV="cert_store_${i}/metrics.csv"
        if [ -f "$CSV" ]; then
            cp "$CSV" "$DEST/client_${i}.csv"
            LINES=$(wc -l < "$CSV")
            echo "  Client $i: $((LINES - 1)) data points"
        else
            echo "  Client $i: NO DATA"
        fi
    done

    echo "[done] $NUM-client test complete."
    echo ""
}

# Run all three conditions
run_test 3
run_test 5
run_test 10

echo "================================================================"
echo " ALL TESTS COMPLETE"
echo " Results in: $OUTDIR/"
echo "================================================================"
ls -la "$OUTDIR"/*/
