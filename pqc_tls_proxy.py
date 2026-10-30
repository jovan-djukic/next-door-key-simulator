"""PQC (ML-DSA-65) mTLS termination shim in front of the Flask KME app.

Python's ssl module (and therefore Flask/Werkzeug's built-in TLS support)
cannot handle ML-DSA-65 certificates. This process terminates the real
ML-DSA-65 mTLS connection (WolfSSL-backed, both server and client cert
required) on the external port, then forwards the plaintext HTTP request to
Flask over loopback, injecting the verified peer certificate's CommonName as
an X-Peer-CN header so the app can authorize the caller without ever seeing
raw TLS state.

One CA for every entity (see docker-compose.yml / certs/generate_pqc_certs.py),
so the handshake only proves that the caller holds *some* cert from that CA.
That doesn't say which kind of entity it is: relays, apps and KMEs all pass.
Deciding who may call what is done per route in server/security.py, from the
CommonName passed on here. A client-supplied X-Peer-CN is removed first, so
that header only ever carries the verified name.

Env vars (see .env.example):
  HOST, PORT        - external address this shim listens on (SAE/KME-facing)
  FLASK_PORT        - loopback port the Flask app binds to
  CA_FILE           - the CA certificate (PEM) every caller must be signed by
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


def _load_pem(path: str) -> str:
    with open(path, 'r') as f:
        return f.read()


def handle_connection(raw_sock, cert_der, pkcs8_der, ca_der, flask_port):
    try:
        peer_addr = raw_sock.getpeername()
    except OSError:
        peer_addr = "?"

    try:
        conn = wolfssl_mldsa.pqc_tls_server_accept(
            raw_sock.fileno(), cert_der, pkcs8_der, ca_der)
    except Exception as e:
        print(f"[pqc-proxy] handshake with {peer_addr} failed: {e}")
        raw_sock.close()
        return

    try:
        request = pqc_http.read_http_message(conn)
        if not request:
            return

        peer_cn = wolfssl_mldsa.parse_cert_subject_cn(conn.peer_cert_der())
        request = pqc_http.strip_header(request, "X-Peer-CN")
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
    ca_der = pqc_http.decode_pem(_load_pem(os.getenv('CA_FILE')))
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
            args=(raw_sock, cert_der, pkcs8_der, ca_der, flask_port),
            daemon=True
        )
        t.start()


if __name__ == '__main__':
    main()
