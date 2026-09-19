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
    script_content: str = ""
    port: int = 8443
    ttl: int = 3600
    psk: Optional[str] = None

class ManualStartRequest(BaseModel):
    host_identifier: str
    port: int = 8443
    ttl: int = 3600
    psk: Optional[str] = None

@router.post("/manual-start")
async def manual_start_prober(req: ManualStartRequest, request: Request):
    analyzer = main_app.get_or_create_analyzer()
    if not analyzer:
        raise HTTPException(status_code=500, detail="Zabbix analyzer not initialized")

    hosts = analyzer.list_hosts(search=req.host_identifier)
    if not hosts:
        raise HTTPException(status_code=404, detail="Host not found in Zabbix")
    
    host_info = hosts[0]
    interfaces = analyzer.client.call("hostinterface.get", {"output": ["ip"], "hostids": host_info["hostid"]})
    if not interfaces:
        raise HTTPException(status_code=400, detail="Host has no IP interfaces")
    
    target_ip = interfaces[0]["ip"]
    psk = req.psk.strip() if req.psk and req.psk.strip() else secrets.token_hex(16)
    
    jass_url = str(request.base_url).rstrip("/")
    
    # Save config in DB
    from jass.core.prober_client import ProberClient
    client = ProberClient(host_id=host_info["hostid"], host_ip=target_ip)
    client.update_psk(psk, req.ttl, req.port)
    client.close()
    
    command = f".\\prober.exe --port {req.port} --ttl {req.ttl} --psk \"{psk}\""
    download_command = f"Invoke-WebRequest -Uri '{jass_url}/static/prober.exe' -OutFile 'prober.exe'"
    oneliner = f"Invoke-WebRequest -Uri '{jass_url}/static/prober.exe' -OutFile 'prober.exe'; .\\prober.exe --port {req.port} --ttl {req.ttl} --psk '{psk}'"
    
    return {
        "status": "ready",
        "ip": target_ip,
        "port": req.port,
        "ttl": req.ttl,
        "psk": psk,
        "command": command,
        "download_command": download_command,
        "oneliner": oneliner
    }


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
    
    # Generate or use provided PSK
    psk = req.psk.strip() if req.psk and req.psk.strip() else secrets.token_hex(16)
    
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
        res = analyzer.client.call("script.execute", {"scriptid": script_id, "hostid": host_info["hostid"]})
        dropper_output = res.get("value", "") if isinstance(res, dict) else str(res)
    except Exception as e:
        logger.error(f"Failed to execute dropper: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to execute dropper: {e}")
    
    # Save PSK and TTL in DB
    from jass.core.prober_client import ProberClient
    client = ProberClient(host_id=host_info["hostid"], host_ip=target_ip)
    client.update_psk(psk, req.ttl, req.port)
    client.close()
    
    # We no longer run script automatically here, we just deploy it. Wait for it to become alive via separate ping loop.
    return {"status": "deployed", "ip": target_ip, "port": req.port, "ttl": req.ttl, "dropper_output": dropper_output}

from jass.core.prober_client import ProberClient
from jass.db.models import ProberTask, HostProperty, HostPropertyValue
from jass.db.database import SessionLocal

@router.post("/execute-task/{task_id}")
async def execute_task(task_id: int, req: DeployRequest):
    # This assumes prober is already deployed.
    # req.host_identifier is the host ID
    db = SessionLocal()
    try:
        task = db.query(ProberTask).filter(ProberTask.id == task_id).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        analyzer = main_app.get_or_create_analyzer()
        hosts = analyzer.list_hosts(search=req.host_identifier)
        if not hosts:
            raise HTTPException(status_code=404, detail="Host not found in Zabbix")
        
        host_info = hosts[0]
        host_id = host_info["hostid"]
        interfaces = analyzer.client.call("hostinterface.get", {"output": ["ip"], "hostids": host_id})
        target_ip = interfaces[0]["ip"] if interfaces else None

        client = ProberClient(host_id=host_id, host_ip=target_ip)
        if not client.is_alive():
            raise HTTPException(status_code=400, detail="Prober is not alive on this host")

        # Execute script
        result = client.execute_script(task.content)
        
        # Check success
        if result.get("exit_code") != 0:
            return {"status": "error", "error": result.get("stderr")}

        # Parsing and Mapping
        parsed_data = {}
        if task.parser_id:
            try:
                # Dynamic exec of parser code
                local_env = {}
                exec(task.parser.code, {}, local_env)
                if "parse" in local_env:
                    parsed_data = local_env["parse"](result.get("stdout", ""))
                else:
                    logger.error("Parser code does not define a 'parse' function")
            except Exception as e:
                logger.error(f"Failed to parse output: {e}")
                return {"status": "error", "error": f"Parser error: {e}"}
        
        # Mapping to HostPropertyValue
        if task.map_to_properties and parsed_data:
            for prop_name, value in parsed_data.items():
                prop = db.query(HostProperty).filter_by(name=prop_name).first()
                if prop:
                    val_record = db.query(HostPropertyValue).filter_by(host_id=host_id, property_id=prop.id).first()
                    if not val_record:
                        val_record = HostPropertyValue(host_id=host_id, property_id=prop.id)
                        db.add(val_record)
                    val_record.value = value
            db.commit()

        return {"status": "success", "parsed_data": parsed_data, "raw_stdout": result.get("stdout")}
    finally:
        db.close()


@router.get("/status/{host_identifier}")
async def prober_status(host_identifier: str):
    analyzer = main_app.get_or_create_analyzer()
    hosts = analyzer.list_hosts(search=host_identifier)
    if not hosts:
        raise HTTPException(status_code=404, detail="Host not found in Zabbix")
    
    host_info = hosts[0]
    host_id = host_info["hostid"]
    interfaces = analyzer.client.call("hostinterface.get", {"output": ["ip"], "hostids": host_id})
    target_ip = interfaces[0]["ip"] if interfaces else None

    client = ProberClient(host_id=host_id, host_ip=target_ip)
    is_alive = client.is_alive()
    client.close()

    return {"host_identifier": host_identifier, "is_alive": is_alive, "ip": target_ip}
