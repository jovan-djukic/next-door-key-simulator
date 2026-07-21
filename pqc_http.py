"""HTTP-over-ML-DSA-65-mTLS helpers.

Shared by pqc_tls_proxy.py (the TLS termination shim in front of Flask) and
the KME-to-KME client code in network/scanner.py and network/broadcaster.py.
Python's ssl module (and therefore `requests`) cannot handle ML-DSA-65
certificates, so all HTTP framing here is done by hand over a WolfSSL
mTLS connection (wolfssl_mldsa.PqcTlsConn).
"""
import base64
import socket

import wolfssl_mldsa


def decode_pem(pem_str: str) -> bytes:
    lines = pem_str.strip().split('\n')
    b64_lines = [line for line in lines if not line.startswith('-----')]
    return base64.b64decode(''.join(b64_lines))


def _content_length(header_blob: bytes) -> int:
    for line in header_blob.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1].strip())
    return 0


def read_http_message(conn) -> bytes:
    """Read one full HTTP message (headers + body) from a connection
    exposing .recv(n). Returns b"" if the peer closes before any data."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return buf
        buf += chunk

    header_end = buf.index(b"\r\n\r\n") + 4
    body = buf[header_end:]
    content_length = _content_length(buf[:header_end])

    while len(body) < content_length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk

    return buf[:header_end] + body


def inject_header(message: bytes, name: str, value: str) -> bytes:
    """Insert a header line right after the request/status line."""
    header_end = message.index(b"\r\n\r\n")
    head, body = message[:header_end], message[header_end:]
    lines = head.split(b"\r\n")
    lines.insert(1, f"{name}: {value}".encode())
    return b"\r\n".join(lines) + body


def split_status_and_body(response: bytes):
    """Split a raw HTTP response into (status_code, body_bytes)."""
    if not response:
        raise ConnectionError("peer closed the connection without sending a response "
                               "(e.g. its certificate was rejected before the request was forwarded)")
    header_blob, _, body = response.partition(b"\r\n\r\n")
    status_line = header_blob.split(b"\r\n", 1)[0].decode()
    status_code = int(status_line.split(" ")[1])
    return status_code, body


def pqc_http_request(method: str, host: str, port: int, path: str,
                     cert_der: bytes, pkcs8_der: bytes, ca_der: bytes,
                     json_body: bytes = None, timeout: float = 30):
    """Act as an ML-DSA-65 mTLS client: issue one HTTP request, return
    (status_code, body_bytes)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        with wolfssl_mldsa.pqc_tls_client_connect(sock.fileno(), cert_der, pkcs8_der, ca_der) as conn:
            if json_body is not None:
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(json_body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode() + json_body
            else:
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
            conn.send(request)
            response = conn.recv_until_close()
    finally:
        sock.close()
    return split_status_and_body(response)
