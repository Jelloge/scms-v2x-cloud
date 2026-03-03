# SCMS-V2X EJBCA Setup (From Scratch)

This guide is for bringing up EJBCA + MariaDB on a Raspberry Pi with Docker, then wiring this RTOS client project to use real endpoints (not `mock://`).

---

## 0) What this project expects

From `include/config.h`, the client is currently hard-coded to these names:

- CA name: `V2X-RootCA`
- Certificate profile: `V2X-Enrollment`
- End entity profile: `V2X-EndEntity`
- Username: `qnx-vehicle-client`
- Password: `steed`

If you use different names in EJBCA, update `config.h` to match.

---

## 1) Docker compose on the Pi

On the EJBCA sever:

```bash
mkdir -p ~/containers/datadbdir
cd ~/containers
nano docker-compose.yml
```

Use:

```yaml
networks:
	access-bridge:
		driver: bridge
	application-bridge:
		driver: bridge

services:
	ejbca-database:
		container_name: ejbca-database
		image: "library/mariadb:latest"
		networks:
			- application-bridge
		environment:
			- MYSQL_ROOT_PASSWORD=foo123
			- MYSQL_DATABASE=ejbca
			- MYSQL_USER=ejbca
			- MYSQL_PASSWORD=ejbca
		volumes:
			- ./datadbdir:/var/lib/mysql:rw

	ejbca:
		hostname: ejbca.local
		container_name: ejbca
		image: keyfactor/ejbca-ce:latest
		depends_on:
			- ejbca-database
		networks:
			- access-bridge
			- application-bridge
		environment:
			- DATABASE_JDBC_URL=jdbc:mariadb://ejbca-database:3306/ejbca?characterEncoding=UTF-8
			- LOG_LEVEL_APP=INFO
			- LOG_LEVEL_SERVER=INFO
			- TLS_SETUP_ENABLED=simple
		ports:
			- "80:8080"
			- "443:8443"
```

Start and watch logs:

```bash
docker compose up -d
docker compose logs -f
```

Admin web:

- `https://<ip>/ejbca/adminweb/`

[In Depth Video (more detailed)](https://www.youtube.com/watch?v=oWC5vsGWXQ4&t=2s)


## 2) EJBCA objects to create

Create these exactly (or change `config.h`):

### 2.1 CA

- Name: `V2X-RootCA`
- Type: self-signed root (for this project/lab)
- **Signing Algorithm:** `SHA256WithRSA`
- **CRL Signing Key:** `crlSignKey = signKey`
- **CA Certificate Subject DN:** `CN=SCMS-Root-CA`
- **Issuer DN:** `CN=SCMS-Root-CA` (self-signed root)
- **Generate CRL Upon Revocation:** **Enabled**
- **CRL Expire Period:** `1d`
- **CRL Overlap Time:** `10m`
- **CRL Issue Interval:** `0m`
- CRL distribution URL
    - ex: http://10.0.0.243/ejbca/publicweb/webdist/certdist?cmd=crl
- Default CRL Issuer
    - ex: CN=SCMS-Root-CA

### 2.2 Certificate Profile

- Name: `V2X-Enrollment`
- Key Usage: `Digital Signature`, `Key Encipherment`
- Extended Key Usage: `Client Authentication`
- CRL Distribution Points: Enabled
- Use CA defined CRL Distribution Point: Enabled
- Available CAs: V2x-RootCA

### 2.3 End Entity Profile

- Name: `V2X-EndEntity`
- Allow username/password enrollment
- Allow REST enrollment
- Default certificate profile: `V2X-Enrollment`
- Available CA: `V2X-RootCA`

### 2.4 End Entity (user)

In RA Web → Add End Entity:

- Username: `qnx-vehicle-client`
- Password: `steed`
- End Entity Profile: `V2X-EndEntity`
- Certificate Profile: `V2X-Enrollment`
- CA: `V2X-RootCA`

---

## 3) Enable REST protocol

If enroll/status endpoints fail or say disabled:

1. Open Admin Web
2. Go to `System Configuration` → `Protocol Configuration / Protocols`
3. Enable `REST Certificate Management` and CRL store
4. Save/apply

---

## 4) Export client-auth cert for API calls (mTLS)

This project uses superadmin cert/key as the **client certificate** for EJBCA API calls.

On machine with Docker access to `ejbca` container:

```bash
docker cp ejbca:/opt/keyfactor/p12/superadmin.p12 .
openssl pkcs12 -in superadmin.p12 -clcerts -nokeys -out superadmin_cert.pem
openssl pkcs12 -in superadmin.p12 -nocerts -nodes -out superadmin_key.pem
```

Or download from adminWeb


Copy into project cert store:

- `cert_store/superadmin_cert.pem`
- `cert_store/superadmin_key.pem`

These are used by:

- `EJBCA_CLIENT_CERT`
- `EJBCA_CLIENT_KEY`

---

## 5) Trust anchor (server verification)

The client trust file path is:

- `cert_store/SCMSRootCA.pem` (via `TRUSTED_CA_CERT_PATH`)

Important:

- URL tells the client **where** to connect.
- `SCMSRootCA.pem` tells the client **who to trust** for TLS.

If `EJBCA_TLS` is enabled (`1`), missing/mismatched CA or hostname causes curl `60` errors.

---

## 6) Endpoint mapping used by this project

In Host/IP mode (`argv[1]` is bare host), `main.c` builds:

- Enroll: `https://<host>/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll`
- Pseudonym: `https://<host>/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll`
- CRL: `http://<host>/ejbca/publicweb/webdist/certdist?cmd=crl`
- Revoke (SOAP): `https://<host>/ejbca/ejbcaws/ejbcaws`

Notes:

- Revoke path here is SOAP (`ejbcaws`), not REST revoke.
- CRL endpoint is from EJBCA public web distribution, not REST base.

---

## 7) Running the client

### Option A: Host/IP mode (recommended for your current code)

```bash
./rtos_client 10.0.0.243
```

This auto-builds all 4 URLs from endpoint macros.

### Option B: Full URL mode

```bash
./rtos_client \
	https://10.0.0.243/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll \
	https://10.0.0.243/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll \
	http://10.0.0.243/ejbca/publicweb/webdist/certdist?cmd=crl \
	https://10.0.0.243/ejbca/ejbcaws/ejbcaws
```

At startup, verify runtime URLs in log:

```text
RTOS client started. enroll=... pseudo=... crl=... revoke=...
```

If any value is `mock://...`, you are still on defaults.

---

## 8) TLS mode in current codebase

Current toggle in `config.h`:

```c
#define EJBCA_TLS 0
```

- `0` = dev/insecure mode (disables peer/host verification)
- `1` = secure mode (requires CA trust + hostname match)

If you run secure mode using IP URL and server cert CN/SAN is DNS-only, you can get:

- `curl=60 (SSL peer certificate or SSH remote key was not OK)`

Fix by either:

- Using cert with SAN matching your host/IP, and trusted CA file, or
- Using a matching DNS name instead of raw IP.

---

## 9) Revocation behavior (important)

Revocation is asynchronous:

1. Client submits revoke request (SOAP)
2. CA processes request
3. CA publishes updated CRL
4. Client fetches CRL every `CRL_REFRESH_SEC`
5. Cert is blocked once serial appears in CRL

So “revoke requested” is not the same as “already revoked in active CRL.”

This project currently behaves like fail-open during propagation: it continues operation until CRL evidence is observed.

---

## 10) Quick troubleshooting

### `Failed to reach endpoint`

- Confirm container ports `80/443` are exposed
- Confirm REST protocol enabled
- Confirm URL path matches current EJBCA version

### `curl=60`

- Check `EJBCA_TLS` mode
- If secure mode: verify `SCMSRootCA.pem`, cert chain, hostname/SAN match

### No revoke events showing

- Confirm revoke path in logs is non-mock
- Confirm revoke trigger path is enabled in `main.c`
- Increase `SIM_REVOCATION_PROBABILITY_PERCENT` temporarily for testing

### CRL never marks cert revoked

- Verify CRL URL is reachable and returning current CRL
- Verify CRL signer chains to trusted CA
- Wait for CA publication + client refresh interval

---

## 11) Security note for production direction

Using superadmin cert on vehicle is acceptable for local lab bring-up, but not for production.

In production, vehicle should not carry CA admin credentials.
