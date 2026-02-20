# Evaluating Cloud-Hosted SCMS Performance for C-V2X Using a QNX RTOS Client

**COMP4900 — Real-Time Operating Systems | Carleton University | Winter 2026**

Shirley Huang · Jasmine Jamali · Darnell Foster · Prabhkirat Dhaliwal · Shihao Jia

---

## Overview

This project evaluates whether a cloud-hosted Security Credential Management System (SCMS) can meet the real-time performance requirements of C-V2X communication. We deploy [EJBCA Community Edition](https://www.ejbca.org/) on AWS as a certificate authority backend and build a multi-threaded QNX Neutrino RTOS client that requests, manages, and uses V2X security credentials while maintaining a 100ms BSM signing deadline.

## Research Question

Can a QNX RTOS vehicle client satisfy C-V2X real-time constraints when provisioning security credentials from a cloud-hosted SCMS backend? We measure end-to-end latency, jitter, and deadline-miss rate, then compare against Chen et al.'s local SCMS baselines [[3]](#references) and the V2X latency requirements from Amjad et al. [[2]](#references).

## Architecture

```
┌─────────────────────────────────┐       HTTPS        ┌──────────────────────────────┐
│        QNX RTOS Client          │  ◄──────────────►  │       AWS Cloud Backend       │
│                                 │                     │                               │
│  Thread 0 (highest priority)    │                     │  EJBCA on EC2 (t3.medium)     │
│    BSM Signing (every 100ms)    │                     │    - Root CA                  │
│                                 │                     │    - Enrollment CA             │
│  Thread 1 (medium priority)     │                     │    - Pseudonym CA              │
│    Certificate Provisioning     │─── REST API ──────► │    - ECDSA P-256 profiles      │
│    (batch of 20 certs)          │                     │                               │
│                                 │                     │  RDS PostgreSQL               │
│  Thread 2 (lowest priority)     │                     │    - Certificate storage       │
│    Performance Monitor          │                     │    - Audit logs                │
│                                 │                     │                               │
│  Shared: certificate store      │                     │  CloudWatch                   │
│  Sync: mutex + condition var    │                     │    - CPU, network, DB metrics  │
└─────────────────────────────────┘                     └──────────────────────────────┘
```

## Tech Stack

| Component | Technology |
|---|---|
| SCMS Backend | EJBCA Community Edition (Docker) |
| Cloud Platform | AWS EC2, RDS, CloudWatch |
| Database | PostgreSQL (AWS RDS) |
| RTOS Client | QNX Neutrino RTOS (C) |
| Crypto | OpenSSL (ECDSA P-256) |
| HTTP Client | libcurl |
| Threading | POSIX pthreads (QNX) |
| Analysis | Python (pandas, matplotlib) |
| Version Control | Git / GitHub |

## RTOS Design

The QNX client runs three threads demonstrating preemptive priority-based scheduling:

- **Thread 0 — BSM Signing (highest priority):** Signs a simulated Basic Safety Message every 100ms using ECDSA P-256. Reads the current certificate from a shared store. Logs deadline compliance per cycle. Models the real-world constraint that vehicles must broadcast signed BSMs 10 times per second [[1]](#references).

- **Thread 1 — Certificate Provisioning (medium priority):** Generates ECDSA P-256 key pairs, creates X.509 CSRs, sends batched HTTPS requests (20 certs per batch) to the EJBCA REST API, receives and parses the certificate response, and swaps new certificates into the shared store under mutex lock.

- **Thread 2 — Performance Monitor (lowest priority):** Timestamps all certificate events, computes per-request latency, and writes metrics to CSV files. Uses mutexes for thread-safe access to shared data.

**Synchronization:** Threads 0 and 1 share a certificate store protected by a mutex. A condition variable signals Thread 0 when enrollment completes. Mutex contention between BSM signing and certificate swapping is measured to evaluate real-time impact.

## Implementation Scope

We simplify Brecht et al.'s full SCMS architecture [[1]](#references):
- Standard X.509 CSRs instead of Butterfly Key Expansion
- EJBCA as a unified CA backend instead of separate RA/PCA/LA components
- Batches of 20 certificates per request (matching Chen et al. [[3]](#references))
- Focus on cloud provisioning latency, not full privacy mechanisms

## Project Phases

### Phase 1: AWS Infrastructure Setup (Weeks 1–2)
- Deploy EJBCA in Docker on EC2 (t3.medium)
- Configure RDS PostgreSQL for certificate storage
- Set up ECDSA P-256 certificate profiles (Root CA, Enrollment CA, Pseudonym CA)
- Configure CloudWatch monitoring
- Verify certificate issuance via REST API with curl

### Phase 2: QNX RTOS Client Development (Weeks 3–4)
- Build multi-threaded QNX application in C
- Implement BSM signing thread with 100ms periodic timer
- Implement certificate provisioning thread with EJBCA REST API integration
- Implement performance monitoring thread with CSV logging
- Set up mutex/condition variable synchronization between threads

### Phase 3: Performance Testing (Weeks 5–6)
- **Latency Testing:** Measure end-to-end certificate batch request latency (mean, median, p95, p99)
- **BSM Deadline Testing:** Measure deadline-miss rate during idle vs active provisioning
- **Load Testing:** Test at 1, 5, 10, and 20 requests per minute
- **Resource Utilization:** Track QNX CPU/memory per thread and AWS CloudWatch metrics

### Phase 4: Analysis & Report (Week 7)
- Generate latency distribution and throughput charts
- Present BSM deadline-miss rates across test conditions
- Compare cloud results against Chen et al.'s baselines [[3, Table 1]](#references)
- Assess viability against V2X latency requirements from Amjad et al. [[2, Table I]](#references)

## Comparison Methodology

Chen et al. [[3]](#references) measured performance on a different SCMS implementation and different hardware (Clientron devices, Chunghwa Telecom SCMS). We use their network round-trip measurements as rough baselines to estimate cloud hosting overhead:

## References

[1] B. Brecht et al., "A Security Credential Management System for V2X Communications," *IEEE Trans. Intelligent Transportation Systems*, vol. 19, no. 12, pp. 3850–3871, Dec. 2018. [IEEE](https://ieeexplore.ieee.org/document/8309336/)

[2] Z. Amjad et al., "Low Latency V2X Applications and Network Requirements: Performance Evaluation," *2018 IEEE Intelligent Vehicles Symposium*, pp. 220–225. [IEEE](https://ieeexplore.ieee.org/document/8500531/)

[3] A. C. H. Chen et al., "Implementation and Performance Analysis of Security Credential Management System Based on IEEE 1609.2 and 1609.2.1 Standards," *2023 IEEE ICMLANT*. [IEEE](https://ieeexplore.ieee.org/document/10372990/)

[4] COMP 4900 Real-Time Operating Systems Course Materials, Carleton University, 2024–2025.

[5] QNX Software Systems, "QNX Neutrino RTOS System Architecture," 2024.

[6] EJBCA Community Edition, PrimeKey Solutions AB. [ejbca.org](https://www.ejbca.org/)

[7] Amazon Web Services, "AWS EC2 and RDS Technical Documentation." [aws.amazon.com](https://aws.amazon.com/)
