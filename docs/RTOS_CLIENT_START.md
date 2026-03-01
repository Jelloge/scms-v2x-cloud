# RTOS Client PKI Start Plan

## What this starter now covers

- Key generation on client (ECDSA P-256)
- CSR generation and CA enrollment request
- Pseudonym batch request
- Certificate artifact storage
- 3-thread runtime skeleton with shared metrics
- CSV logging for performance analysis

## Build

```bash
make
```

## Run

```bash
./rtos_client [enrollment_url] [pseudonym_url]
```

Default URLs are mock endpoints, so cloud is not required for first tests.

## Thread model

- **Thread 0:** signer loop, 100ms cycle, deadline miss accounting
- **Thread 1:** provisioning loop (PKI enrollment + pseudonym)
- **Thread 2:** monitor loop (CSV + console metrics)

## Suggested test progression

1. **Offline mock mode**
   - Run with defaults (`mock://...`) to validate full client path.
2. **Local CA mode**
   - Point URLs to localhost service to validate real HTTP/TLS behavior.
3. **AWS mode**
   - Bring EC2 up for bounded test windows only.
   - Run scripted load tests and export logs.

## Required hardening before final report

- Replace placeholder JSON contract with exact EJBCA request/response model.
- Enforce TLS verification and CA trust pinning.
- Add bounded queues and explicit synchronization between signing and cert rollover.
- Compute p50/p95/p99 from `metrics.csv` and include in analysis.
