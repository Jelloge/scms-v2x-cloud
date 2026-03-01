# RTOS Client PKI Start

## What this starter now covers

- Key generation on client (ECDSA P-256)
- CSR generation and CA enrollment request
- Pseudonym batch request
- Certificate artifact storage
- 3-thread runtime skeleton with shared metrics
- CSV logging for performance analysis

## Thread model

- **Thread 0:** signer loop, 100ms cycle, deadline miss accounting
- **Thread 1:** provisioning loop (PKI enrollment + pseudonym)
- **Thread 2:** monitor loop (CSV + console metrics)
