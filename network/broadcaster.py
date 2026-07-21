import json
import os
from urllib.parse import urlsplit

import pqc_http
import wolfssl_mldsa


class Broadcaster:
    def __init__(self):
        self.other_kmes = os.getenv('OTHER_KMES').split(',')
        self.cert_der = pqc_http.decode_pem(open(os.getenv('KME_CERT')).read())
        self.ca_der = pqc_http.decode_pem(open(os.getenv('CA_FILE')).read())
        sk_raw = pqc_http.decode_pem(open(os.getenv('KME_KEY')).read())
        self.pkcs8_der = wolfssl_mldsa.pkcs8_mldsa65_der(sk_raw)

    def send_keys(self, master_sae_id: str, slave_sae_id: str, keys: list) -> None:
        self.__broadcast('/api/v1/kme/keys/exchange', {
            'master_sae_id': master_sae_id, 'slave_sae_id': slave_sae_id, 'keys': keys
        })

    def remove_keys(self, master_sae_id: str, slave_sae_id: str, keys: list) -> None:
        self.__broadcast('/api/v1/kme/keys/remove', {
            'master_sae_id': master_sae_id, 'slave_sae_id': slave_sae_id, 'keys': keys
        })

    def __broadcast(self, path: str, data: dict) -> None:
        body = json.dumps(data, default=str).encode()

        for kme in self.other_kmes:
            parts = urlsplit(kme)
            try:
                pqc_http.pqc_http_request(
                    'POST', parts.hostname, parts.port, path,
                    self.cert_der, self.pkcs8_der, self.ca_der,
                    json_body=body
                )
            except Exception as exception:
                print(f'Unable to broadcast to KME {kme}.')
                print(exception)
