#!/usr/bin/env python3
"""Generate ML-DSA-65 identity certificates for the 4 KME containers.

Run this on the host (not in a container) — it needs the CA's private key,
which is never shipped to the KME containers themselves. This is the one CA
for the whole qkd_client project (pqc_ca/): controller, relays, apps and KMEs.
Output lands in ./certs (this script's directory by default), which the
Dockerfile bakes into the image via `COPY . ...` — so re-run this and
`docker compose up --build` whenever certs change; there is no runtime
bind-mount for them.

The containers get: the CA certificate (for verifying every caller and peer
KME) and their own CA-signed cert + key. Which entity may use which endpoint is
decided by certificate CN, see server/security.py.

This replaces the original next-door-key-simulator's certs/generate.sh: that
script shelled out to openssl for RSA certs, which can't produce ML-DSA-65
certificates, so cert generation moved to Python using the same WolfSSL
bindings (wolfssl_mldsa.py) the rest of the qkd_client project uses.

Usage (run from this certs/ directory -- defaults already point at
../../../pqc_ca, i.e. the qkd_client project root):
  python3 generate_pqc_certs.py
"""
import argparse
import base64
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# qkd_client project root, three levels above this script
# (external/next-door-key-simulator/certs/). wolfssl_mldsa.py isn't vendored
# into the simulator fork since it's bind-mounted into containers at
# runtime; anchoring to __file__ (not cwd) means this script also works
# when invoked as `python3 certs/generate_pqc_certs.py` from elsewhere.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_PROJECT_ROOT))

import wolfssl_mldsa  # noqa: E402

ALGORITHM = "ML-DSA-65"

KME_NAMES = ["kme-link0-start", "kme-link0-end", "kme-link1-start", "kme-link1-end"]

# ==================== Minimal DER helpers (X.509 leaf cert, ML-DSA-65) ====================

_OID_MLDSA65 = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])
_OID_CN = bytes([0x55, 0x04, 0x03])


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(val)) + val


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _int_der(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big') or b"\x00"
    return _tlv(0x02, b)


def _oid(raw: bytes) -> bytes:
    return _tlv(0x06, raw)


def _utf8str(s: str) -> bytes:
    return _tlv(0x0C, s.encode())


def _utctime(dt: datetime) -> bytes:
    return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())


def _bitstr(data: bytes) -> bytes:
    return _tlv(0x03, b"\x00" + data)


def _ctx0(*items: bytes) -> bytes:
    return _tlv(0xA0, b"".join(items))


def _mldsa65_alg_id() -> bytes:
    return _seq(_oid(_OID_MLDSA65))


def _x509_name(cn: str) -> bytes:
    return _seq(_set(_seq(_oid(_OID_CN), _utf8str(cn))))


def _spki(pk: bytes) -> bytes:
    return _seq(_mldsa65_alg_id(), _bitstr(pk))


def build_leaf_cert_der(subject_cn: str, public_key: bytes,
                        issuer_cn: str, ca_sk: bytes, serial: int) -> bytes:
    not_before = datetime.now(timezone.utc).replace(tzinfo=None)
    not_after = not_before + timedelta(days=825)
    tbs = _seq(
        _ctx0(_int_der(2)),
        _int_der(serial),
        _mldsa65_alg_id(),
        _x509_name(issuer_cn),
        _seq(_utctime(not_before), _utctime(not_after)),
        _x509_name(subject_cn),
        _spki(public_key),
    )
    signer = wolfssl_mldsa.Signature(ALGORITHM, ca_sk)
    sig = signer.sign(tbs)
    return _seq(tbs, _mldsa65_alg_id(), _bitstr(sig))


def encode_pem(data: bytes, label: str) -> str:
    b64 = base64.b64encode(data).decode('ascii')
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def decode_pem(pem_str: str) -> bytes:
    lines = pem_str.strip().split('\n')
    b64_lines = [line for line in lines if not line.startswith('-----')]
    return base64.b64decode(''.join(b64_lines))


def main():
    parser = argparse.ArgumentParser(description="Generate ML-DSA-65 certs for the KME containers")
    parser.add_argument("--ca-cert", default=str(_PROJECT_ROOT / "pqc_ca" / "ca_certificate.pem"))
    parser.add_argument("--ca-key", default=str(_PROJECT_ROOT / "pqc_ca" / "ca_private_key.pem"))
    parser.add_argument("--output-dir", default=str(Path(__file__).resolve().parent))
    args = parser.parse_args()

    ca_cert_pem = Path(args.ca_cert).read_text()
    ca_key_pem = Path(args.ca_key).read_text()
    ca_sk = decode_pem(ca_key_pem)
    ca_der = decode_pem(ca_cert_pem)
    issuer_cn = wolfssl_mldsa.parse_cert_subject_cn(ca_der)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "ca.crt.pem").write_text(ca_cert_pem)
    print(f"Wrote {out_dir / 'ca.crt.pem'} (issuer CN={issuer_cn})")

    for i, name in enumerate(KME_NAMES, start=1):
        signer = wolfssl_mldsa.Signature(ALGORITHM)
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()

        cert_der = build_leaf_cert_der(name, pk, issuer_cn, ca_sk, serial=i)
        assert wolfssl_mldsa.verify_cert_der(cert_der, ca_der), f"cert for {name} failed self-check"

        (out_dir / f"{name}.crt.pem").write_text(encode_pem(cert_der, "CERTIFICATE"))
        (out_dir / f"{name}.key.pem").write_text(encode_pem(sk, "ML-DSA-65 PRIVATE KEY"))
        print(f"Wrote {name}.crt.pem / {name}.key.pem (CN={name}, signed by {issuer_cn})")


if __name__ == "__main__":
    main()
