import asyncio
from collections import defaultdict
from datetime import datetime
import logging
import os
from jass.core.settings import get_setting
import secrets
import time
import requests
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional, Any, List, Dict, Tuple
from jass.core.prober_crypto import encrypt_payload, decrypt_payload
from jass.core.prober_client import ProberClient
from jass.db.models import ProberTask, HostProperty, HostPropertyValue
def _get_analyzer():
    import jass.ui.app as main_app
    return main_app.get_or_create_analyzer()

logger = logging.getLogger("jass.prober")

router = APIRouter(prefix="/api/prober", tags=["Prober"])

# In-memory per-host activity logs buffer
_HOST_LOGS: Dict[str, List[str]] = defaultdict(list)

# In-memory cache for resolved Zabbix host info and interface IP
# host_identifier -> (host_info_dict, target_ip, expire_timestamp)
_HOST_RESOLVE_CACHE: Dict[str, Tuple[Dict[str, Any], Optional[str], float]] = {}

def _resolve_host(analyzer, host_identifier: str) -> Tuple[Dict[str, Any], Optional[str]]:
    now = time.time()
    if host_identifier in _HOST_RESOLVE_CACHE:
        host_info, target_ip, expiry = _HOST_RESOLVE_CACHE[host_identifier]
        if now < expiry:
            return host_info, target_ip

    hosts = analyzer.list_hosts(search=host_identifier)
    if not hosts:
        raise HTTPException(status_code=404, detail=f"Host '{host_identifier}' not found in Zabbix")
    
    host_info = hosts[0]
    interfaces = analyzer.client.call("hostinterface.get", {"output": ["ip"], "hostids": host_info["hostid"]})
    target_ip = interfaces[0]["ip"] if interfaces else None

    # Cache for 5 minutes
    _HOST_RESOLVE_CACHE[host_identifier] = (host_info, target_ip, now + 300)
    if host_info["hostid"] != host_identifier:
        _HOST_RESOLVE_CACHE[host_info["hostid"]] = (host_info, target_ip, now + 300)

    return host_info, target_ip

def log_host_event(host_identifier: str, message: str):
    """Appends an event to the host's activity log buffer."""
    now_str = datetime.now().strftime("%H:%M:%S")
    entry = f"[{now_str}] {message}"
    logs = _HOST_LOGS[str(host_identifier)]
    logs.append(entry)
    if len(logs) > 200:
        del logs[0:len(logs)-200]

class ManualStartRequest(BaseModel):
    host_identifier: str
    port: int = Field(default_factory=lambda: int(get_setting('PROBER_DEFAULT_PORT', 10052)))
    ttl: int = Field(default_factory=lambda: max(1800, int(get_setting('PROBER_DEFAULT_TTL', 1800))))
    psk: Optional[str] = None

class ExecuteTaskRequest(BaseModel):
    host_identifier: str
    port: Optional[int] = None
    ttl: Optional[int] = None
    psk: Optional[str] = None

# Backwards-compatible alias
DeployRequest = ExecuteTaskRequest

@router.post("/manual-start")
def manual_start_prober(req: ManualStartRequest, request: Request):
    try:
        analyzer = _get_analyzer()
        if not analyzer:
            raise HTTPException(status_code=500, detail="Zabbix analyzer not initialized")

        host_info, target_ip = _resolve_host(analyzer, req.host_identifier)
        if not target_ip:
            raise HTTPException(status_code=400, detail="Host has no IP interfaces")
        
        psk = req.psk.strip() if req.psk and req.psk.strip() else secrets.token_hex(16)
        req.ttl = max(1800, req.ttl)
        
        jass_url = os.environ.get("JASS_BASE_URL", "").rstrip("/") or str(request.base_url).rstrip("/")
        
        # Save config in DB
        client = ProberClient(host_id=host_info["hostid"], host_ip=target_ip)
        try:
            client.update_psk(psk, max(1800, req.ttl), req.port)
        finally:
            client.close()
        
        log_host_event(host_info["hostid"], f"Configured parameters: Port={req.port}, TTL={req.ttl}s, PSK length={len(psk)}")
        if req.host_identifier != host_info["hostid"]:
            log_host_event(req.host_identifier, f"Configured parameters: Port={req.port}, TTL={req.ttl}s")
        
        command = f".\\prober.exe --port {req.port} --ttl {req.ttl} --psk \"{psk}\""
        download_command = f"(New-Object System.Net.WebClient).DownloadFile('{jass_url}/static/prober.exe', 'prober.exe')"
        oneliner = f"(New-Object System.Net.WebClient).DownloadFile('{jass_url}/static/prober.exe', 'prober.exe'); .\\prober.exe --port {req.port} --ttl {req.ttl} --psk '{psk}'"
        
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
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Manual start prober error:")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop/{host_identifier}")
@router.post("/terminate/{host_identifier}")
def stop_prober(host_identifier: str):
    """Sends termination signal to the prober agent, removes firewall rule, and deletes executable."""
    try:
        analyzer = _get_analyzer()
        host_info, target_ip = _resolve_host(analyzer, host_identifier)
        host_id = host_info["hostid"]
        if not target_ip:
            raise HTTPException(status_code=400, detail="Host has no IP interfaces")

        client = ProberClient(host_id=host_id, host_ip=target_ip)
        try:
            log_host_event(host_id, f"Sending termination & self-destruct signal to {target_ip}:{client.config.port}...")
            terminated = client.terminate()
            client.config.is_active = False
            client.db.commit()
            if terminated:
                log_host_event(host_id, "Prober accepted termination command. Windows firewall rule removed and executable scheduled for deletion.")
            else:
                log_host_event(host_id, "Prober did not respond to termination (agent may already be stopped).")
            return {"status": "terminated", "success": terminated}
        finally:
            client.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Stop prober error:")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs/{host_identifier}")
def prober_logs(host_identifier: str, tail: int = 50):
    """Fetches real-time combined logs: server-side activity events and remote agent logs."""
    try:
        analyzer = _get_analyzer()
        host_info, target_ip = _resolve_host(analyzer, host_identifier)
        host_id = host_info["hostid"]

        # Server-side logs for this host
        server_logs = list(_HOST_LOGS.get(host_id, []))
        if host_identifier != host_id:
            server_logs += [l for l in _HOST_LOGS.get(host_identifier, []) if l not in server_logs]

        agent_logs = []
        is_alive = False
        port = None
        psk = None

        if target_ip:
            client = ProberClient(host_id=host_id, host_ip=target_ip)
            try:
                is_alive = client.is_alive()
                port = client.config.port
                psk = client.config.psk
                if is_alive:
                    agent_logs = client.fetch_logs(tail=tail)
            finally:
                client.close()

        return {
            "host_identifier": host_identifier,
            "host_id": host_id,
            "is_alive": is_alive,
            "ip": target_ip,
            "port": port,
            "psk": psk,
            "server_logs": server_logs,
            "agent_logs": agent_logs,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Prober logs error:")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute-task/{task_id}")
def execute_task(task_id: int, req: ExecuteTaskRequest):
    db = SessionLocal()
    try:
        task = db.query(ProberTask).filter(ProberTask.id == task_id).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        analyzer = _get_analyzer()
        host_info, target_ip = _resolve_host(analyzer, req.host_identifier)
        host_id = host_info["hostid"]

        client = ProberClient(host_id=host_id, host_ip=target_ip, db=db)
        try:
            if not client.is_alive():
                log_host_event(host_id, f"Cannot execute task '{task.name}': Prober is not alive on {target_ip}:{client.config.port}")
                raise HTTPException(status_code=400, detail="Prober is not alive on this host")

            log_host_event(host_id, f"Executing task '{task.name}'...")
            result = client.execute_script(task.content)
            
            exit_code = result.get("exit_code", 0)
            raw_stdout = result.get("stdout", "")
            stderr_output = result.get("stderr", "")

            # Parsing first
            parsed_data = {}
            if task.parser_id and task.parser and task.parser.code:
                try:
                    local_env = {}
                    exec(task.parser.code, local_env)
                    if "parse" in local_env:
                        parsed_data = local_env["parse"](raw_stdout)
                    else:
                        logger.error("Parser code does not define a 'parse' function")
                except Exception as e:
                    logger.error(f"Failed to parse output: {e}")
                    log_host_event(host_id, f"Parser error for task '{task.name}': {e}")

            success = (exit_code == 0) or bool(parsed_data)
            if not success:
                err_msg = stderr_output or raw_stdout or f"Task exited with code {exit_code}"
                log_host_event(host_id, f"Task '{task.name}' failed with exit code {exit_code}: {err_msg}")
                return {"status": "error", "error": err_msg}

            log_host_event(host_id, f"Task '{task.name}' finished successfully (output size: {len(raw_stdout)} bytes)")

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

            return {"status": "success", "parsed_data": parsed_data, "raw_stdout": raw_stdout}
        finally:
            client.close()
    finally:
        db.close()


@router.get("/status/{host_identifier}")
def prober_status(host_identifier: str):
    analyzer = _get_analyzer()
    host_info, target_ip = _resolve_host(analyzer, host_identifier)
    host_id = host_info["hostid"]

    is_alive = False
    port = None
    psk = None
    ttl = None

    if target_ip:
        client = ProberClient(host_id=host_id, host_ip=target_ip)
        try:
            is_alive = client.is_alive()
            port = client.config.port
            psk = client.config.psk
            ttl = client.config.ttl_seconds
        finally:
            client.close()

    return {
        "host_identifier": host_identifier,
        "host_id": host_id,
        "is_alive": is_alive,
        "ip": target_ip,
        "port": port,
        "psk": psk,
        "ttl": ttl,
    }
