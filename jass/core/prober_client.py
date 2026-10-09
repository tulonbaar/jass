import os
from jass.core.settings import get_setting
import requests
import json
import secrets
from jass.db.database import SessionLocal
from jass.db.models import ProberHostConfig
from jass.core.prober_crypto import encrypt_payload, decrypt_payload
import logging

from typing import Optional, Any
from sqlalchemy.orm import Session

logger = logging.getLogger("jass.prober_client")

class ProberClient:
    def __init__(self, host_id: str, host_ip: str, db: Optional[Session] = None):
        self.host_id = host_id
        self.host_ip = host_ip
        self._external_db = db is not None
        self.db = db if db is not None else SessionLocal()
        self.config = self._get_or_create_config()

    def _get_or_create_config(self) -> ProberHostConfig:
        config = self.db.query(ProberHostConfig).filter_by(host_id=self.host_id).first()
        if not config:
            psk = secrets.token_hex(16)
            config = ProberHostConfig(host_id=self.host_id, port=10052, psk=psk)
            self.db.add(config)
            self.db.commit()
        return config

    def get_config(self) -> Optional[ProberHostConfig]:
        return self.db.query(ProberHostConfig).filter_by(host_id=self.host_id).first()

    def close(self):
        if not self._external_db and self.db:
            self.db.close()

    def update_psk(self, psk: str, ttl: int, port: int = 10052):
        self.config.psk = psk
        self.config.ttl_seconds = ttl
        self.config.port = port
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
                timeout=int(get_setting('PROBER_EXECUTION_TIMEOUT', 600))
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to communicate with prober: {e}")
            raise Exception(f"Failed to communicate with prober: {e}")

        try:
            res = decrypt_payload(resp.content, self.config.psk)
            import base64
            for field in ('stdout', 'stderr'):
                b64_field = f"{field}_b64"
                if b64_field in res and res[b64_field]:
                    try:
                        raw_bytes = base64.b64decode(res[b64_field])
                        try:
                            res[field] = raw_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                res[field] = raw_bytes.decode('cp852')
                            except UnicodeDecodeError:
                                res[field] = raw_bytes.decode('cp1250', errors='replace')
                    except Exception as e:
                        logger.warning(f"Failed to decode {b64_field}: {e}")
            return res
        except Exception as e:
            logger.error(f"Failed to decrypt/parse prober response: {e}")
            raise Exception(f"Failed to decrypt/parse prober response: {e}")

    def fetch_logs(self, tail: int = 100) -> list:
        url = f"http://{self.host_ip}:{self.config.port}/logs"
        encrypted_req = encrypt_payload({"tail": tail}, self.config.psk)
        try:
            resp = requests.post(
                url,
                data=encrypted_req,
                headers={'Content-Type': 'application/octet-stream'},
                timeout=5
            )
            resp.raise_for_status()
            data = decrypt_payload(resp.content, self.config.psk)
            return data.get("logs", [])
        except Exception as e:
            logger.debug(f"Failed to fetch logs from prober: {e}")
            return []

    def terminate(self) -> bool:
        url = f"http://{self.host_ip}:{self.config.port}/terminate"
        encrypted_req = encrypt_payload({"action": "terminate"}, self.config.psk)
        try:
            resp = requests.post(
                url,
                data=encrypted_req,
                headers={'Content-Type': 'application/octet-stream'},
                timeout=5
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Failed to terminate prober: {e}")
            return False

