import os

import flask
from flask import Request


def ensure_valid_sae_id(request: Request):
    """Authorize the caller.

    The pqc_tls_proxy in front of this app already required a client
    certificate signed by CA_FILE to complete the ML-DSA-65 mTLS handshake
    at all (see pqc_tls_proxy.py / wolfssl_mldsa.pqc_tls_server_accept), and
    passes the verified certificate's CommonName through as X-Peer-CN. There
    is no per-request cert available here to re-verify — this only checks
    that the already-authenticated caller is the SAE this KME is attached to.
    Every entity's cert comes from that one CA, so this check is what keeps
    other relays, apps and KMEs out of the SAE endpoints.
    """
    sae_id = request.headers.get('X-Peer-CN', '')

    if sae_id != os.getenv('ATTACHED_SAE_ID'):
        print('Peer certificate common name does not match the attached_sae_id value!')
        flask.abort(401)


def ensure_valid_kme_peer(request: Request):
    """Authorize a caller of the KME-to-KME endpoints (/api/v1/kme/...).

    Only the KMEs named in OTHER_KME_CNS get through: relays and apps hold
    certs from the same CA as KMEs, and so do KMEs serving other links.
    """
    peer_cn = request.headers.get('X-Peer-CN', '')

    if not peer_cn or peer_cn not in os.getenv('OTHER_KME_CNS', '').split(','):
        print(f'Refused {peer_cn!r} on a KME-to-KME endpoint: not a peer KME!')
        flask.abort(401)
