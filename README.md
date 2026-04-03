# Evaluating Cloud-Hosted SCMS Performance for C-V2X Using a QNX RTOS Client

**COMP4900 -- Real-Time Operating Systems | Carleton University | Winter 2026**

Shirley Huang, Jasmine Jamali, Darnell Foster, Prabhkirat Dhaliwal, Shihao Jia

---

## Links

- **Final Report:** [*Link to report*]
- **Presentation:** [*Link to presentation*]

---

## Overview

This project evaluates whether a cloud-hosted Security Credential Management System (SCMS) can meet the real-time performance requirements of C-V2X (Cellular Vehicle-to-Everything) communication. We deploy [EJBCA Community Edition](https://www.ejbca.org/) on AWS EC2 as a certificate authority backend and build a multi-threaded QNX Neutrino RTOS client that requests, manages, and uses V2X security credentials while maintaining a 100 ms BSM (Basic Safety Message) signing deadline.

## Research Question

> Can a QNX RTOS vehicle client satisfy C-V2X real-time constraints when provisioning security credentials from a cloud-hosted SCMS backend?

We measure end-to-end latency, jitter, and deadline-miss rate across multiple provisioning rates and client counts, then compare against Chen et al.'s local SCMS baselines and the V2X latency requirements from Amjad et al.

## Architecture

```
+-----------------------------------+          HTTPS          +-------------------------------+
|        QNX RTOS Client            | <---------------------> |       AWS Cloud Backend        |
|                                   |                         |                                |
|  Thread 0 (Priority 20)          |                         |  EJBCA CE on EC2 (t3.medium)   |
|    BSM Signing -- every 100 ms   |                         |    - Root CA                   |
|    ECDSA P-256, soft deadline    |                         |    - Enrollment CA             |
|                                   |                         |    - Pseudonym CA              |
|  Thread 1 (Priority 15)          |                         |    - ECDSA P-256 profiles      |
|    Certificate Provisioning      |--- REST API ----------> |                                |
|    Enrollment + pseudonym batch  |                         |  MariaDB                       |
|    (20 certs per batch)          |                         |    - Certificate storage       |
|                                   |                         |                                |
|  Thread 2 (Priority 10)          |                         |  CRL Distribution Point        |
|    Metrics Logger (CSV)          |                         |    - Revocation checking       |
|                                   |                         |                                |
|  Shared: certificate store       |                         +-------------------------------+
|  Sync: mutex + condition variable |
+-----------------------------------+
```

## Tech Stack

| Component | Technology |
|---|---|
| SCMS Backend | EJBCA Community Edition (Docker on EC2) |
| Cloud Platform | AWS EC2 (t3.medium), IP: 18.118.3.99 |
| Database | MariaDB (EJBCA internal) |
| RTOS | QNX Neutrino 8.0 (x86_64 VM) |
| Client Language | C (POSIX pthreads) |
| Crypto | OpenSSL (ECDSA P-256, SHA-256) |
| HTTP | libcurl (REST API + mTLS) |
| Scheduling | SCHED_RR preemptive priority-based |
| Analysis | Python (pandas, matplotlib) |

## RTOS Design

The client runs three POSIX threads with `SCHED_RR` preemptive scheduling:

- **Thread 0 -- BSM Signer (priority 20):** Signs a Basic Safety Message every 100 ms using ECDSA P-256. Checks CRL revocation status before signing. Records deadline misses when a cycle exceeds 100 ms (soft deadline).

- **Thread 1 -- Provisioner (priority 15):** Generates ECDSA key pairs, creates X.509 CSRs, enrolls with EJBCA via REST API, and requests pseudonym certificate batches (20 certs per batch). Swaps new certificates into the shared store under mutex lock.

- **Thread 2 -- Metrics Logger (priority 10):** Samples all latency metrics and writes to CSV every ~10 seconds. Tracks enrollment latency, pseudonym batch latency, BSM signing latency, mutex wait time, and deadline misses.

**Synchronization:** A mutex protects the shared certificate store. A condition variable signals Thread 0 when the first enrollment completes so signing can begin.

## Project Structure

```
scms-v2x-cloud/
|-- src/
|   |-- main.c                  # Multi-threaded RTOS client (entry point)
|   |-- pki.c                   # Key generation, CSR, enrollment, signing
|   |-- http.c                  # libcurl wrapper for EJBCA REST API
|   |-- metrics.c               # CSV metrics logging
|   |-- storage.c               # File system utilities
|   |-- certRevocation.c        # CRL download, parsing, revocation check
|   |-- simCertRevocation.c     # Simulated revocation for testing
|   +-- analysis_script.py      # Single-client data analysis
|
|-- include/                    # Header files (config.h, pki.h, etc.)
|-- scripts/
|   |-- run_multi.sh            # Run N concurrent clients against EJBCA
|   |-- run_multi_all.sh        # Full multi-client suite (3, 5, 10 clients)
|   |-- analyze_multi.py        # Per-run multi-client analysis
|   |-- analyze_multi_results.py    # Cross-condition comparison
|   +-- analyze_multi_results_v2.py # Enhanced analysis with combined figures
|
|-- data/
|   |-- baseline.csv            # Single-client: BSM signing only
|   |-- rate_60s.csv            # Single-client: 60s provisioning interval
|   |-- rate_12s.csv            # Single-client: 12s provisioning interval
|   |-- rate_6s.csv             # Single-client: 6s provisioning interval
|   |-- rate_3s.csv             # Single-client: 3s provisioning interval
|   |-- resource_*.csv          # CPU/memory/context switch data
|   |-- multi_3c/               # 3-client test (client_1..3.csv)
|   |-- multi_5c/               # 5-client test (client_1..5.csv)
|   +-- multi_10c/              # 10-client test (client_1..10.csv)
|
|-- analysis_output/            # Generated figures (PNG) and summary CSVs
|-- cert_store/                 # Runtime certificate storage (gitignored)
|-- Makefile                    # QNX build (qcc compiler)
|-- MakefileNOTQNX              # Linux build (gcc)
|-- run_tests_linux.sh          # Single-client test harness
+-- setup.md                    # EJBCA server configuration guide
```

## Building

**QNX (requires QNX SDP 8.0):**
```bash
make            # uses qcc with -V12.2.0,gcc_ntox86_64
```

**Linux:**
```bash
make -f MakefileNOTQNX
```

**Dependencies:** libcurl, OpenSSL (libssl + libcrypto), POSIX pthreads

## Running

```bash
# Single client (default)
./rtos_client <EJBCA_IP> [provision_period_seconds] [client_id]

# Examples
./rtos_client 18.118.3.99              # baseline (no provisioning)
./rtos_client 18.118.3.99 5            # provision every 5 seconds
./rtos_client 18.118.3.99 5 3          # client ID 3 (uses cert_store_3/)

# Multi-client test suite (3, 5, 10 clients)
cd scripts && bash run_multi_all.sh
```

**Prerequisites:** The EJBCA server must be running and accessible. The `cert_store/` directory must contain `superadmin_cert.pem` and `superadmin_key.pem` for mTLS authentication.

## Key Results

### Single-Client (QNX RTOS)

| Metric | Baseline | Rate 60s | Rate 12s | Rate 6s | Rate 3s |
|---|---|---|---|---|---|
| BSM Signing (mean) | 0.186 ms | 0.186 ms | 0.185 ms | 0.186 ms | 0.186 ms |
| Deadline Misses | 0 | 5 | 5 | 5 | 5 |
| Miss Rate | 0% | 0.39% | 0.40% | 0.40% | 0.38% |
| Enrollment Latency | -- | 1,154 ms | 1,175 ms | 1,174 ms | 1,161 ms |

- BSM signing uses < 0.2% of the 100 ms budget at all provisioning rates
- All deadline misses occur during initial CRL refresh (first 5-7 seconds), not from provisioning
- SCHED_RR priority scheduling fully isolates signing from provisioning load

### Multi-Client Scalability (Proof-of-Concept)

| Metric | 3 Clients | 5 Clients | 10 Clients |
|---|---|---|---|
| Enrollment Latency (ms) | 517 +/- 197 | 1,078 +/- 250 | 1,668 +/- 594 |
| Pseudonym Batch (ms) | 3,680 +/- 25 | 5,259 +/- 370 | 21,457 +/- 18,270 |
| Deadline Misses / client | 6.0 | 6.0 | 5.9 |

- Cloud enrollment latency scales linearly with concurrent clients (EJBCA contention)
- EJBCA saturates at 10 clients (pseudonym batch 5.8x slower than 3-client baseline)
- BSM signing remains constant regardless of client count (CPU-bound, network-independent)
- Multi-client tests ran on host platform as proof-of-concept; cloud-facing metrics are platform-independent

## Implementation Scope

This project simplifies Brecht et al.'s full SCMS architecture:
- Standard X.509 CSRs instead of Butterfly Key Expansion
- EJBCA as a unified CA backend (not separate RA/PCA/LA components)
- Batches of 20 certificates per request (matching Chen et al.)
- CRL-based revocation with 25% simulated revocation probability
- Focus on cloud provisioning latency and real-time deadline compliance

## Future Work

- **Native RTOS multi-client testing:** Deploy on multiple QNX hardware targets (e.g., Raspberry Pi cluster) or QNX hypervisor partitions to measure RTOS-specific behaviors (priority inversion, mutex contention, network stack pressure) under concurrent cloud load
- **EJBCA horizontal scaling:** Test with EJBCA clustering or read replicas to support hundreds of concurrent vehicles
- **Hardware Security Module (HSM) integration:** Replace software ECDSA with HSM-backed signing for production-grade key protection
- **Full SCMS topology:** Implement separate Registration Authority, Pseudonym CA, and Linkage Authority per IEEE 1609.2.1
- **Over-the-air provisioning:** Test certificate renewal over cellular networks with realistic V2X radio latency

## References

1. B. Brecht et al., "A Security Credential Management System for V2X Communications," *IEEE Trans. ITS*, vol. 19, no. 12, pp. 3850-3871, Dec. 2018.
2. Z. Amjad et al., "Low Latency V2X Applications and Network Requirements," *IEEE IV*, 2018, pp. 220-225.
3. A. C. H. Chen et al., "Implementation and Performance Analysis of SCMS Based on IEEE 1609.2," *IEEE ICMLANT*, 2023.
4. COMP 4900 Real-Time Operating Systems Course Materials, Carleton University, 2024-2025.
5. QNX Software Systems, "QNX Neutrino RTOS System Architecture," 2024.
6. EJBCA Community Edition, PrimeKey Solutions AB. [ejbca.org](https://www.ejbca.org/)
