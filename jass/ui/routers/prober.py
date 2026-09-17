import asyncio
import logging
import secrets
import time
import requests
from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel
from typing import Optional, Any
from jass.core.prober_crypto import encrypt_payload, decrypt_payload
import jass.ui.app as main_app # To use state["analyzer"]

logger = logging.getLogger("jass.prober")

router = APIRouter(prefix="/api/prober", tags=["Prober"])

class DeployRequest(BaseModel):
    host_identifier: str
    script_content: str
    port: int = 8443
    ttl: int = 3600

def run_prober_job(host_ip: str, psk: str, port: int, ttl: int, script: str):
    """Background job that pings the prober and executes the script when ready."""
    logger.info(f"Starting prober job for {host_ip}:{port}")
    # Ping loop
    ready = False
    for i in range(30):
        try:
            resp = requests.get(f"http://{host_ip}:{port}/ping", timeout=2)
            if resp.status_code == 200 and resp.text == "PONG":
                ready = True
                break
        except Exception:
            pass
        time.sleep(1)

    if not ready:
        logger.error(f"Prober on {host_ip}:{port} did not become ready.")
        return

    logger.info(f"Prober ready on {host_ip}:{port}. Sending script...")
    
    # Send script
    payload = {"script": script}
    encrypted_data = encrypt_payload(payload, psk)
    
    try:
        # Long timeout for execution
        resp = requests.post(f"http://{host_ip}:{port}/execute", data=encrypted_data, timeout=ttl)
        if resp.status_code == 200:
            result = decrypt_payload(resp.content, psk)
            logger.info(f"Prober execution finished on {host_ip}")
            # TODO: save result to DB or state
        else:
            logger.error(f"Prober execute failed: {resp.status_code}")
    except Exception as e:
        logger.error(f"Prober connection lost or error: {e}")

@router.post("/deploy")
async def deploy_prober(req: DeployRequest, request: Request, background_tasks: BackgroundTasks):
    analyzer = main_app.get_or_create_analyzer()
    if not analyzer:
        raise HTTPException(status_code=500, detail="Zabbix analyzer not initialized")

    # Resolve host to IP (using Zabbix Analyzer)
    hosts = analyzer.list_hosts(search=req.host_identifier)
    if not hosts:
        raise HTTPException(status_code=404, detail="Host not found in Zabbix")
    
    host_info = hosts[0]
    # Pick agent IP
    interfaces = analyzer.client.call("hostinterface.get", {"output": ["ip"], "hostids": host_info["hostid"]})
    if not interfaces:
        raise HTTPException(status_code=400, detail="Host has no IP interfaces")
    
    target_ip = interfaces[0]["ip"]
    
    # Generate random PSK
    psk = secrets.token_hex(16)
    
    # We dynamically get JASS URL from the incoming request so the dropper knows where to download prober.exe from
    jass_url = str(request.base_url).rstrip("/")
    # Using curl/wget on windows via powershell (Invoke-WebRequest)
    dropper_ps = f"""
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri '{jass_url}/static/prober.exe' -OutFile 'C:\\Windows\\Temp\\prober.exe'
Start-Process -WindowStyle Hidden -FilePath 'C:\\Windows\\Temp\\prober.exe' -ArgumentList '--port {req.port} --ttl {req.ttl} --psk {psk}'
"""
    
    logger.info(f"Deploying prober to {target_ip} from {jass_url}")
    
    script_name = "JASS Prober Dropper"
    available_scripts = analyzer.client.call("script.get", {"hostids": [host_info["hostid"]]})
    target_script = next((sc for sc in available_scripts if sc.get("name") == script_name), None)
            
    if not target_script:
        logger.info(f"Creating Zabbix script '{script_name}'")
        try:
            created = analyzer.client.call(
                "script.create",
                {
                    "name": script_name,
                    "command": dropper_ps,
                    "type": 0,  # 0 = Script
                    "scope": 2,  # 2 = Manual host action
                    "execute_on": 0,  # 0 = Zabbix agent
                    "description": "Deploys ephemeral JASS Prober agent",
                },
            )
            script_id = created["scriptids"][0]
        except Exception as e:
            logger.error(f"Failed to create dropper script: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to create dropper script: {e}")
    else:
        script_id = target_script["scriptid"]
        # Always update script to ensure correct payload and jass_url
        analyzer.client.call("script.update", {"scriptid": script_id, "command": dropper_ps})

    logger.info(f"Executing dropper on {target_ip} (scriptid: {script_id})")
    try:
        analyzer.client.call("script.execute", {"scriptid": script_id, "hostid": host_info["hostid"]})
    except Exception as e:
        logger.error(f"Failed to execute dropper: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to execute dropper: {e}")
    
    background_tasks.add_task(run_prober_job, target_ip, psk, req.port, req.ttl, req.script_content)
    
    return {"status": "deployed", "ip": target_ip, "port": req.port, "ttl": req.ttl}
