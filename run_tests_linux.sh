#!/bin/sh
#
# run_tests_linux.sh - runs all 5 tests on Linux host with SCHED_RR
#
# usage: sudo ./run_tests_linux.sh <EJBCA_IP> <EJBCA_SSH_KEY>
# e.g.:  sudo ./run_tests_linux.sh 18.118.3.99 /path/to/scms-key.pem
#
# produces 10 files in data/:
#   baseline.csv, rate_60s.csv, rate_12s.csv, rate_6s.csv, rate_3s.csv
#   resource_baseline.csv, resource_60s.csv, resource_12s.csv, resource_6s.csv, resource_3s.csv

EJBCA_IP="$1"
EJBCA_KEY="$2"
DURATION=150
DATA_DIR="./data"

if [ -z "$EJBCA_IP" ] || [ -z "$EJBCA_KEY" ]; then
    echo "usage: sudo $0 <EJBCA_IP> <EJBCA_SSH_KEY>"
    echo "e.g.:  sudo $0 18.118.3.99 /home/user/scms-key.pem"
    exit 1
fi

mkdir -p "$DATA_DIR"

####################################
# EJBCA ENTITY RESET
####################################

reset_ejbca_entity() {
    echo "  Resetting EJBCA end entity..."
    ssh -i "$EJBCA_KEY" -o StrictHostKeyChecking=no ubuntu@"$EJBCA_IP" \
        "sudo docker exec ejbca /opt/keyfactor/bin/ejbca.sh ra setendentitystatus --username qnx-vehicle-client -S 10 2>&1 && \
         sudo docker exec ejbca /opt/keyfactor/bin/ejbca.sh ra setpwd --username qnx-vehicle-client --password steed 2>&1" \
        > /dev/null 2>&1
    echo "  Entity reset done."
}

####################################
# RESOURCE CAPTURE (Linux)
####################################

# uses /proc/PID/stat and /proc/PID/status instead of pidin
# $1 = PID of rtos_client
# $2 = output file

capture_resources() {
    clientPid=$1
    outFile=$2

    startTime=$(date +%s)
    echo "=== resource capture start ===" > "$outFile"

    while kill -0 "$clientPid" 2>/dev/null; do
        now=$(date +%s)
        elapsed=$((now - startTime))

        echo "" >> "$outFile"
        echo "--- t=${elapsed}s ---" >> "$outFile"

        # per-thread CPU times
        echo "[thread times]" >> "$outFile"
        for t in /proc/"$clientPid"/task/*/stat; do
            if [ -f "$t" ]; then
                cat "$t" >> "$outFile" 2>/dev/null
                echo "" >> "$outFile"
            fi
        done

        # memory + context switches
        echo "[status]" >> "$outFile"
        cat /proc/"$clientPid"/status >> "$outFile" 2>/dev/null

        sleep 5
    done

    echo "" >> "$outFile"
    echo "=== resource capture end ===" >> "$outFile"
}

####################################
# RUN ONE TEST
####################################

# $1 = provision rate in seconds (0 = baseline)
# $2 = label (e.g. "baseline", "rate_60s")

run_one_test() {
    rate=$1
    label=$2

    echo ""
    echo "========================================"
    echo "  TEST: $label  (rate=${rate}s, ${DURATION}s)"
    echo "========================================"

    # reset EJBCA entity before each real-EJBCA test
    if [ "$rate" -ne 0 ]; then
        reset_ejbca_entity
    fi

    # clean stale certs from previous run
    rm -f ./cert_store/enrollment_cert.pem ./cert_store/enrollment_key.pem
    rm -f ./cert_store/enrollment.csr.pem ./cert_store/pseudonym_bundle.pem
    rm -f ./cert_store/metrics.csv

    # start client (sudo already applied to this script)
    ./rtos_client "$EJBCA_IP" "$rate" &
    clientPid=$!
    echo "  PID: $clientPid"

    # start resource capture alongside it
    capture_resources "$clientPid" "${DATA_DIR}/resource_${label}.csv" &
    capturePid=$!

    # let it run
    sleep "$DURATION"

    # stop client gracefully
    kill -INT "$clientPid" 2>/dev/null
    sleep 2
    kill -9 "$clientPid" 2>/dev/null
    wait "$clientPid" 2>/dev/null
    wait "$capturePid" 2>/dev/null

    # save the latency csv
    if [ -f "./cert_store/metrics.csv" ]; then
        cp "./cert_store/metrics.csv" "${DATA_DIR}/${label}.csv"
        echo "  -> ${DATA_DIR}/${label}.csv"
    else
        echo "  !! metrics.csv missing"
    fi

    echo "  -> ${DATA_DIR}/resource_${label}.csv"
    echo ""

    # cooldown
    sleep 5
}

####################################
# RUN ALL 5 TESTS
####################################

echo ""
echo "Full test suite against $EJBCA_IP"
echo "~15 min total (${DURATION}s x 5 tests)"
echo ""

run_one_test  0   "baseline"
run_one_test  60  "rate_60s"
run_one_test  12  "rate_12s"
run_one_test  6   "rate_6s"
run_one_test  3   "rate_3s"

echo ""
echo "========================================"
echo "  DONE"
echo "========================================"
echo ""
echo "Latency CSVs:"
ls -la "${DATA_DIR}"/baseline.csv "${DATA_DIR}"/rate_*.csv 2>/dev/null
echo ""
echo "Resource CSVs:"
ls -la "${DATA_DIR}"/resource_*.csv 2>/dev/null
echo ""
echo "Next step: scp data/ back to laptop and run python3 analyze.py"
