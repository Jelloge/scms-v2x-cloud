# Evaluating Cloud-Hosted SCMS Performance for C-V2X Using a QNX RTOS Client

 Jasmine. J, Shirley Huang, Darnell Foster, Prabhkirat Dhaliwal, Shihao Jia

---

- **Final Report:** [*[Link to report](https://docs.google.com/document/d/1vLUufsQ8IP6OiJb8fktPx5EV1XL8FxbjcpM1gjk-zG8/edit?tab=t.0)*]

---

## Overview

This project evaluates whether a cloud-hosted Security Credential Management System (SCMS) can meet the real-time performance requirements of C-V2X (Cellular Vehicle-to-Everything) communication. We deploy [EJBCA Community Edition](https://www.ejbca.org/) on AWS EC2 as a certificate authority backend and build a multi-threaded QNX Neutrino RTOS client that requests, manages, and uses V2X security credentials while maintaining a 100 ms BSM (Basic Safety Message) signing deadline.

## Research Question

> Can a QNX RTOS vehicle client satisfy C-V2X real-time constraints when provisioning security credentials from a cloud-hosted SCMS backend?

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
