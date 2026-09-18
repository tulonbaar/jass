import requests
import json
import secrets
from jass.db.database import SessionLocal
from jass.db.models import ProberHostConfig
from jass.core.prober_crypto import encrypt_payload, decrypt_payload
import logging

logger = logging.getLogger("jass.prober_client")

class ProberClient:
    def __init__(self, host_id: str, host_ip: str):
        self.host_id = host_id
        self.host_ip = host_ip
        self.db = SessionLocal()
        self.config = self._get_or_create_config()

    def _get_or_create_config(self) -> ProberHostConfig:
        config = self.db.query(ProberHostConfig).filter_by(host_id=self.host_id).first()
        if not config:
            psk = secrets.token_hex(16)
            config = ProberHostConfig(host_id=self.host_id, port=8443, psk=psk)
            self.db.add(config)
            self.db.commit()
        return config

    def close(self):
        self.db.close()

    def update_psk(self, psk: str, ttl: int):
        self.config.psk = psk
        self.config.ttl_seconds = ttl
        self.db.commit()

    def is_alive(self) -> bool:
        url = f"http://{self.host_ip}:{self.config.port}/ping"
        try:
            resp = requests.get(url, timeout=3)
            return resp.status_code == 200 and resp.text == "PONG"
        except requests.RequestException:
            return False

    def execute_script(self, script_content: str) -> dict:
        url = f"http://{self.host_ip}:{self.config.port}/execute"
        
        encrypted_req = encrypt_payload({"script": script_content}, self.config.psk)
        
        try:
            resp = requests.post(
                url, 
                data=encrypted_req, 
                headers={'Content-Type': 'application/octet-stream'},
                timeout=30
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to communicate with prober: {e}")
            raise Exception(f"Failed to communicate with prober: {e}")

        try:
            return decrypt_payload(resp.content, self.config.psk)
        except Exception as e:
            logger.error(f"Failed to decrypt/parse prober response: {e}")
            raise Exception(f"Failed to decrypt/parse prober response: {e}")

