# Next Door Key Simulator (qkd_client fork)

Quantum key distribution (QKD) key management entity (KME) simulator based on
the [ETSI GS QKD 014 V1.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf)
standard.

This is a fork of [CreepPork/next-door-key-simulator](https://github.com/CreepPork/next-door-key-simulator),
adapted to replace qukaydee.com in the QTEE-V project. The
original used plain Python `ssl` (RSA/ECDSA certs) for mTLS; since Python's
`ssl` module can't handle ML-DSA-65 certificates, this fork adds a
`pqc_tls_proxy.py` shim (WolfSSL-backed, via the qkd_client project's
`wolfssl_mldsa.py`) that terminates real ML-DSA-65 mTLS in front of the
otherwise-unmodified Flask app. See `pqc_tls_proxy.py`, `pqc_http.py`,
`server/security.py`, and `certs/generate_pqc_certs.py` for the specifics.

## Abbreviations

- CA - Certificate Authority
- KME - Key Management Entity (server)
- SAE - Secure Application Entity (client)
- QKD - Quantum Key Distribution

## Requirements

- Docker
- Docker Compose
- The qkd_client PQC CA already generated at `../../pqc_ca/` (see the qkd_client
  project's `generate_pqc_ca.py`). It is the one CA for the controller, relays,
  apps and KMEs, see `docker-compose.yml`.

## Installation

1. `python3 certs/generate_pqc_certs.py` (defaults already point at
   `../../pqc_ca/`; pass `--ca-cert`/`--ca-key` to override)
2. `docker compose up -d --build`

Certs are baked into the image at build time (not bind-mounted), so re-run
step 1 and `docker compose up -d --build` again whenever certs change.

## Introduction

The Docker Compose file runs 4 KMEs — 2 QKD links (one per pair of adjacent
relays in the qkd_client chain), each link backed by 2 KME instances
(start side / end side).

The KMEs communicate with each other using proprietary endpoints to share the generated keys between the other KMEs. (
This would be implemented by a real KME using quantum protocols).

The KMEs discover each other by only giving their host address (configurable in the `OTHER_KMES` environment variable).

All entities share one CA, so endpoints are authorized by certificate CN:

| Endpoints | Allowed CN |
|---|---|
| `/api/v1/keys/...` (SAE) | `ATTACHED_SAE_ID` only |
| `/api/v1/kme/...` (KME-to-KME) | `OTHER_KME_CNS` only, so relays and apps get 401 |

`OTHER_KME_CNS` also lists the CN expected from each `OTHER_KMES` entry when this KME calls it, in the same order.

### Implementation details

**Do not use** this _simulator_ in any type of production environment because, in no way, this simulator is secure.

The given QKD KME simulator currently only supports `POST` method on `/enc_keys` and `/dec_keys` endpoints, no support
for `GET` is given.

### Troubleshooting

#### Socket hang up

As per the standard, there is an authentication process with mututal TLS certificates.
If this error occurs the most likely reason, is that you are not giving the client TLS certificates.

If you are using Postman, this can be easily enabled by:

- using the respective KME's SAE auto-generated certificates (available in the `certs` directory);
- and [configuring Postman](https://learning.postman.com/docs/sending-requests/certificates/#adding-client-certificates)
  as follows: Cog > Settings > Certificates > Client Certificates > Add Certificate.

![postman-config](docs/1.png)

#### Waiting for response

Sometimes, the Docker containers will get stuck and are not either responding to user requests, or doing any kind of
sync operations between the KMEs.

It might be caused by host network interruptions, both containers starting at the same time and not being able to
connect, and possibly more scenarios.

The best option, is to just restart either 1 or both containers using this command in your terminal:

```bash
docker compose restart
docker compose logs -f
```

This will restart both containers, and afterward enter following mode for the console logs. Then you should see the new
log entries starting to appear.

## Disclaimer

This project originally has been developed for LatQN (Latvian National Quantum Network) project in association with
LVRTC (Latvian State Radio and Television Center).
