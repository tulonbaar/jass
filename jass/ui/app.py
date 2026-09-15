"""
JASS - Just Another System Sniffer
Web UI Server (FastAPI + Uvicorn)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from jass.analyzers.zabbix_analyzer import ZabbixAnalyzer
from jass.core.client import ZabbixAPIException, ZabbixAuthException
from jass.core.models import HostAnalysisPayload
from jass.core.prompt_builder import LLMPromptBuilder

logger = logging.getLogger("jass.ui")

app = FastAPI(
    title="JASS - Just Another System Sniffer",
    description="Windows & Hyper-V Telemetry Sniffer and LLM Analysis Hub",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global session state and cache
state: Dict[str, Any] = {
    "analyzer": None,
    "zabbix_url": os.getenv("ZABBIX_URL", ""),
    "api_token": os.getenv("ZABBIX_API_TOKEN") or os.getenv("ZABBIX_TOKEN", ""),
    "username": os.getenv("ZABBIX_USER") or os.getenv("ZABBIX_USERNAME", ""),
    "password": os.getenv("ZABBIX_PASSWORD", ""),
    "verify_ssl": True,
    "cached_payloads": {},  # host_id -> HostAnalysisPayload
}


class ConnectRequest(BaseModel):
    url: str
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = True


class AnalyzeHostRequest(BaseModel):
    host_identifier: str
    run_remote_probe: bool = False
    script_name: Optional[str] = None
    probe_key: Optional[str] = None


class SavePayloadRequest(BaseModel):
    host_name: str
    payload: Dict[str, Any]
    output_dir: Optional[str] = "."


def get_or_create_analyzer() -> ZabbixAnalyzer:
    """Returns active ZabbixAnalyzer instance or creates a new one from state."""
    if state["analyzer"] is not None:
        return state["analyzer"]

    if not state["zabbix_url"]:
        raise HTTPException(status_code=400, detail="Zabbix URL not configured.")

    try:
        analyzer = ZabbixAnalyzer(
            url=state["zabbix_url"],
            api_token=state["api_token"] or None,
            username=state["username"] or None,
            password=state["password"] or None,
            verify_ssl=state["verify_ssl"],
        )
        analyzer.connect()
        state["analyzer"] = analyzer
        return analyzer
    except (ZabbixAuthException, ZabbixAPIException) as err:
        raise HTTPException(status_code=401, detail=str(err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Zabbix client initialization error: {exc}")


@app.get("/api/status")
async def api_status():
    """Returns Zabbix API connection status."""
    connected = False
    version = None
    error = None
    if state["analyzer"]:
        try:
            version = state["analyzer"].client.get_version()
            connected = True
        except Exception as e:
            error = str(e)
            state["analyzer"] = None
    elif state["zabbix_url"]:
        try:
            an = get_or_create_analyzer()
            version = an.client.get_version()
            connected = True
        except Exception as e:
            error = str(e)

    return {
        "connected": connected,
        "zabbix_url": state["zabbix_url"],
        "has_token": bool(state["api_token"]),
        "has_credentials": bool(state["username"] and state["password"]),
        "zabbix_version": version,
        "error": error,
    }


@app.post("/api/connect")
async def api_connect(req: ConnectRequest):
    """Configures and tests Zabbix API connection."""
    state["zabbix_url"] = req.url
    state["api_token"] = req.token or ""
    state["username"] = req.username or ""
    state["password"] = req.password or ""
    state["verify_ssl"] = req.verify_ssl
    state["analyzer"] = None

    try:
        analyzer = get_or_create_analyzer()
        version = analyzer.client.get_version()
        return {
            "success": True,
            "message": f"Connected successfully to Zabbix API (version {version}).",
            "version": version,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/groups")
async def api_groups():
    """Retrieves list of host groups."""
    analyzer = get_or_create_analyzer()
    try:
        groups = analyzer.list_hostgroups()
        return {"groups": groups}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/hosts")
async def api_hosts(group_id: Optional[str] = None, search: Optional[str] = None):
    """Retrieves list of hosts."""
    analyzer = get_or_create_analyzer()
    try:
        group_ids = [group_id] if group_id else None
        hosts = analyzer.list_hosts(group_ids=group_ids, search=search)
        return {"hosts": hosts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/probes")
async def api_probes():
    """Lists built-in remote probes available in the JASS probe catalog."""
    return {"probes": ZabbixAnalyzer.list_available_probes()}


@app.post("/api/analyze/host")
async def api_analyze_host(req: AnalyzeHostRequest):
    """Performs host telemetry analysis and returns JSON payload."""
    analyzer = get_or_create_analyzer()
    try:
        payload = analyzer.analyze_host(
            host_identifier=req.host_identifier,
            run_remote_probe=req.run_remote_probe,
            script_name=req.script_name,
            probe_key=req.probe_key,
        )
        state["cached_payloads"][payload.host_name] = payload
        state["cached_payloads"][payload.host_id] = payload

        return {
            "success": True,
            "payload": payload.model_dump(),
            "llm_prompt": LLMPromptBuilder.build_user_prompt(payload),
            "system_prompt": LLMPromptBuilder.SYSTEM_PROMPT,
        }
    except Exception as e:
        logger.exception("Error during host analysis:")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/save")
async def api_save_payload(req: SavePayloadRequest):
    """Saves analysis payload as [host_name]_analysis.json."""
    try:
        pydantic_payload = HostAnalysisPayload(**req.payload)
        saved_file = ZabbixAnalyzer.save_analysis_json(pydantic_payload, output_dir=req.output_dir or ".")
        return {"success": True, "file_path": saved_file}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/", response_class=HTMLResponse)
async def get_index():
    """Serves the main Web Dashboard interface."""
    template_path = Path(__file__).parent / "templates" / "index.html"
    if template_path.exists():
        return HTMLResponse(content=template_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>JASS UI Template Not Found</h1>", status_code=404)


def start_ui_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    default_url: Optional[str] = None,
    default_token: Optional[str] = None,
    default_user: Optional[str] = None,
    default_password: Optional[str] = None,
    verify_ssl: bool = True,
) -> None:
    """Starts Uvicorn server hosting JASS Web Dashboard."""
    if default_url:
        state["zabbix_url"] = default_url
    if default_token:
        state["api_token"] = default_token
    if default_user:
        state["username"] = default_user
    if default_password:
        state["password"] = default_password
    state["verify_ssl"] = verify_ssl

    uvicorn.run(app, host=host, port=port, log_level="info")
