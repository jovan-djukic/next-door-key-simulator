"""PQC (ML-DSA-65) mTLS termination shim in front of the Flask KME app.

Python's ssl module (and therefore Flask/Werkzeug's built-in TLS support)
cannot handle ML-DSA-65 certificates. This process terminates the real
ML-DSA-65 mTLS connection (WolfSSL-backed, both server and client cert
required) on the external port, then forwards the plaintext HTTP request to
Flask over loopback, injecting the verified peer certificate's CommonName as
an X-Peer-CN header so the app can authorize the caller without ever seeing
raw TLS state.

Two trust domains, one CA each (see docker-compose.yml / certs/generate_pqc_certs.py):
  - A relay calling an SAE-facing endpoint (/api/v1/keys/...) presents its
    one PQC identity cert, signed by the Relay CA.
  - A peer KME calling an internal endpoint (/api/v1/kme/...) presents its
    own server cert, signed by the KME CA.
These are deliberately separate CAs, so the connecting party's cert is only
ever checked against the ONE CA appropriate for the endpoint it's calling --
not "accepted if it matches either". Which CA that is isn't known until the
HTTP request (and therefore its path) has been read, which only happens
*after* the TLS handshake completes -- so the handshake itself is done with
pqc_tls_server_accept_unverified() (deferred verification), and the actual
verify_cert_der() check happens here once the path is known.

Env vars (see .env.example):
  HOST, PORT        - external address this shim listens on (SAE/KME-facing)
  FLASK_PORT        - loopback port the Flask app binds to
  CA_FILE           - KME CA certificate (PEM) -- trusted for peer-KME calls
  RELAY_CA_FILE     - Relay CA certificate (PEM) -- trusted for relay calls
  KME_CERT          - this KME's own ML-DSA-65 certificate (PEM)
  KME_KEY           - this KME's own ML-DSA-65 private key (raw-key PEM wrapper)
"""
import os
import socket
import threading

from dotenv import load_dotenv

import pqc_http
import wolfssl_mldsa

load_dotenv('.env')

KME_INTERNAL_PREFIX = "/api/v1/kme/"


def _load_pem(path: str) -> str:
    with open(path, 'r') as f:
        return f.read()


def _request_path(request: bytes) -> str:
    """Extract the path from an HTTP request's start line, e.g.
    b"GET /api/v1/keys/R0/status HTTP/1.1\\r\\n..." -> "/api/v1/keys/R0/status"."""
    start_line = request.split(b"\r\n", 1)[0]
    parts = start_line.split(b" ")
    return parts[1].decode() if len(parts) >= 2 else ""


def handle_connection(raw_sock, cert_der, pkcs8_der, kme_ca_der, relay_ca_der, flask_port):
    try:
        peer_addr = raw_sock.getpeername()
    except OSError:
        peer_addr = "?"

    try:
        # ctx_ca_der is only a formality for WolfSSL's context setup here --
        # the real check happens below once we know which CA applies.
        conn = wolfssl_mldsa.pqc_tls_server_accept_unverified(
            raw_sock.fileno(), cert_der, pkcs8_der, kme_ca_der)
    except Exception as e:
        print(f"[pqc-proxy] handshake with {peer_addr} failed: {e}")
        raw_sock.close()
        return

    try:
        request = pqc_http.read_http_message(conn)
        if not request:
            return

        path = _request_path(request)
        expected_ca = kme_ca_der if path.startswith(KME_INTERNAL_PREFIX) else relay_ca_der

        peer_cert_der = conn.peer_cert_der()
        if not wolfssl_mldsa.verify_cert_der(peer_cert_der, expected_ca):
            print(f"[pqc-proxy] rejecting {peer_addr}: cert did not verify against the "
                  f"{'KME' if expected_ca is kme_ca_der else 'Relay'} CA for {path}")
            return

        peer_cn = wolfssl_mldsa.parse_cert_subject_cn(peer_cert_der)
        request = pqc_http.inject_header(request, "X-Peer-CN", peer_cn)

        with socket.create_connection(("127.0.0.1", flask_port), timeout=30) as flask_sock:
            flask_sock.sendall(request)
            response = b""
            while True:
                chunk = flask_sock.recv(4096)
                if not chunk:
                    break
                response += chunk

        conn.send(response)
    except Exception as e:
        print(f"[pqc-proxy] error handling {peer_addr}: {e}")
    finally:
        conn.close()
        raw_sock.close()


def main():
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT'))
    flask_port = int(os.getenv('FLASK_PORT'))

    cert_der = pqc_http.decode_pem(_load_pem(os.getenv('KME_CERT')))
    kme_ca_der = pqc_http.decode_pem(_load_pem(os.getenv('CA_FILE')))
    relay_ca_der = pqc_http.decode_pem(_load_pem(os.getenv('RELAY_CA_FILE')))
    sk_raw = pqc_http.decode_pem(_load_pem(os.getenv('KME_KEY')))
    pkcs8_der = wolfssl_mldsa.pkcs8_mldsa65_der(sk_raw)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(16)
    print(f"[pqc-proxy] ML-DSA-65 mTLS listening on {host}:{port}, forwarding to 127.0.0.1:{flask_port}")

    while True:
        raw_sock, _ = listener.accept()
        t = threading.Thread(
            target=handle_connection,
            args=(raw_sock, cert_der, pkcs8_der, kme_ca_der, relay_ca_der, flask_port),
            daemon=True
        )
        t.start()


if __name__ == '__main__':
    main()
