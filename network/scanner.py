import json
import os
import threading
from urllib.parse import urlsplit

import pqc_http
import wolfssl_mldsa


class Scanner:
    def __init__(self, kme_list: list, kme_lock: threading.Lock):
        self.kme_list = kme_list
        self.kme_lock = kme_lock
        self.stop = threading.Event()
        self.other_kmes = pqc_http.other_kmes()

        self.cert_der = pqc_http.decode_pem(open(os.getenv('KME_CERT')).read())
        self.ca_der = pqc_http.decode_pem(open(os.getenv('CA_FILE')).read())
        sk_raw = pqc_http.decode_pem(open(os.getenv('KME_KEY')).read())
        self.pkcs8_der = wolfssl_mldsa.pkcs8_mldsa65_der(sk_raw)

    def start(self) -> None:
        while not self.stop.is_set():
            # Fetched without kme_lock: every request handler takes it, so two
            # KMEs scanning each other while holding it would deadlock until
            # the proxy's timeout.
            fetched = []

            for kme, kme_cn in self.other_kmes:
                try:
                    parts = urlsplit(kme)
                    status, body = pqc_http.pqc_http_request(
                        'GET', parts.hostname, parts.port, '/api/v1/kme/status',
                        self.cert_der, self.pkcs8_der, self.ca_der, kme_cn
                    )
                    if status != 200:
                        print(f'KME {kme} returned status {status}.')
                        continue

                    data = json.loads(body.decode())
                    fetched.append(data)
                except Exception as exception:
                    print(f'Unable to fetch KME status for {kme}.')
                    print(exception)

            self.kme_lock.acquire(blocking=True)

            old_kme_list = list(map(lambda x: x['KME_ID'], self.kme_list))

            self.kme_list.clear()
            self.kme_list.extend(fetched)

            new_kme_list = set(list(map(lambda x: x['KME_ID'], self.kme_list)) + old_kme_list)

            if len(self.kme_list) == 0 and len(old_kme_list) > 0:
                print('Lost all KMEs from the domain!')
            elif len(self.kme_list) != 0 and len(new_kme_list) != len(old_kme_list):
                print('Refreshed KME statuses, established new domain of KMEs:')
                print(self.kme_list)

            self.kme_lock.release()
            self.stop.wait(15)

    def find_kme(self, sae_id: str) -> tuple[str, str] | None:
        if os.getenv('ATTACHED_SAE_ID') == sae_id:
            return os.getenv('KME_ID'), os.getenv('ATTACHED_SAE_ID')

        for value in self.kme_list:
            if value['SAE_ID'] == sae_id:
                return value['KME_ID'], value['SAE_ID']

        return None
