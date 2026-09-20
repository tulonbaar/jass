"""
JASS - Just Another System Sniffer
Web UI Server (FastAPI + Uvicorn)
"""

from __future__ import annotations

import logging
import os
from dotenv import load_dotenv
load_dotenv(override=True)
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Depends
from jass.ui.routers_zabbix_scripts import router as zabbix_scripts_router
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from jass.db.database import init_db, SessionLocal, get_db
from sqlalchemy.orm import Session
import json

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

app.include_router(zabbix_scripts_router)

from jass.db.seeds import seed_db

@app.on_event("startup")
def on_startup():
    init_db()
    seed_db()
    
    from jass.core.settings import get_setting
    state["zabbix_url"] = get_setting("ZABBIX_URL", "")
    state["api_token"] = get_setting("ZABBIX_API_TOKEN", "")
    state["username"] = get_setting("ZABBIX_USER", "")
    state["password"] = get_setting("ZABBIX_PASSWORD", "")
    state["verify_ssl"] = get_setting("ZABBIX_VERIFY_SSL", "true").lower() == "true"
    
    # Setup logging level
    import logging
    log_level = get_setting("LOG_LEVEL", "INFO").upper()
    numeric_level = getattr(logging, log_level, logging.INFO)
    logging.getLogger().setLevel(numeric_level)
    logging.getLogger("jass").setLevel(numeric_level)



from fastapi.staticfiles import StaticFiles

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static directory for prober.exe downloads
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

from jass.ui.routers import prober, admin, host_properties
app.include_router(prober.router)
app.include_router(admin.router)
app.include_router(host_properties.router)

# Global session state and cache
state: Dict[str, Any] = {
    "analyzer": None,
    "zabbix_url": "",
    "api_token": "",
    "username": "",
    "password": "",
    "verify_ssl": True,
    "cached_payloads": {},
}  # host_id -> HostAnalysisPayload


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
    zscript_id: Optional[int] = None


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
def api_status():
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
def api_connect(req: ConnectRequest):
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
def api_groups(db: Session = Depends(get_db)):
    """Retrieves list of host groups from DB, filtered by Zabbix Host Groups setting."""
    from jass.db.models import ZabbixHostGroup, SystemSetting
    groups = db.query(ZabbixHostGroup).all()
    
    setting = db.query(SystemSetting).filter_by(key="zabbix_host_groups").first()
    if setting and setting.value:
        allowed = {g.strip() for g in setting.value.split(",") if g.strip()}
        if allowed:
            groups = [g for g in groups if g.groupid in allowed]
            
    return {"groups": [{"groupid": g.groupid, "name": g.name} for g in groups]}

@app.get("/api/admin/groups")
def api_admin_groups(db: Session = Depends(get_db)):
    """Retrieves ALL host groups from DB for the admin panel settings."""
    from jass.db.models import ZabbixHostGroup
    groups = db.query(ZabbixHostGroup).all()
    return {"groups": [{"groupid": g.groupid, "name": g.name} for g in groups]}

@app.post("/api/admin/sync-groups")
def sync_groups(db: Session = Depends(get_db)):
    """Syncs host groups from Zabbix API to DB."""
    from jass.db.models import ZabbixHostGroup
    analyzer = get_or_create_analyzer()
    try:
        groups = analyzer.list_hostgroups()
        # Upsert
        existing = {g.groupid: g for g in db.query(ZabbixHostGroup).all()}
        for g in groups:
            if g["groupid"] in existing:
                existing[g["groupid"]].name = g["name"]
            else:
                db.add(ZabbixHostGroup(groupid=g["groupid"], name=g["name"]))
        db.commit()
        return {"status": "ok", "count": len(groups)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/hosts")
def api_hosts(group_id: Optional[str] = None, search: Optional[str] = None):
    """Retrieves list of hosts."""
    from jass.db.database import SessionLocal
    from jass.db.models import SystemSetting
    
    analyzer = get_or_create_analyzer()
    try:
        if group_id:
            group_ids = [group_id]
        else:
            db = SessionLocal()
            try:
                setting = db.query(SystemSetting).filter_by(key="zabbix_host_groups").first()
                if setting and setting.value:
                    group_ids = [g.strip() for g in setting.value.split(",") if g.strip()]
                else:
                    group_ids = None
            finally:
                db.close()
                
        hosts = analyzer.list_hosts(group_ids=group_ids, search=search)
        return {"hosts": hosts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/probes")
def api_probes():
    """Lists built-in remote probes available in the JASS probe catalog."""
    return {"probes": ZabbixAnalyzer.list_available_probes()}


@app.post("/api/analyze/host")
def api_analyze_host(req: AnalyzeHostRequest):
    """Performs host telemetry analysis and returns JSON payload."""
    analyzer = get_or_create_analyzer()
    try:
        payload = analyzer.analyze_host(
            host_identifier=req.host_identifier,
            run_remote_probe=req.run_remote_probe,
            script_name=req.script_name,
            probe_key=req.probe_key,
        )


        return {
            "success": True,
            "payload": payload.model_dump(),
            "llm_prompt": LLMPromptBuilder.build_user_prompt(payload),
            "system_prompt": LLMPromptBuilder.SYSTEM_PROMPT,
        }
    except Exception as e:
        logger.exception("Error during host analysis:")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/export-json/{host_id}")
def api_export_json(host_id: str):
    """Exports all host properties as a unified JSON structure."""
    from jass.db.database import SessionLocal
    from jass.db.models import HostPropertyValue, HostProperty
    
    analyzer = get_or_create_analyzer()
    try:
        hosts = analyzer.list_hosts(search=host_id)
        if not hosts:
            db_host_id = host_id
        else:
            db_host_id = hosts[0].get("hostid", host_id)
            
        db = SessionLocal()
        try:
            props = db.query(HostProperty).all()
            prop_map = {p.id: p.name for p in props}
            
            values = db.query(HostPropertyValue).filter_by(host_id=str(db_host_id)).all()
            
            export_data = {"host_id": str(db_host_id), "host_name_query": host_id}
            for v in values:
                p_name = prop_map.get(v.property_id)
                if p_name:
                    export_data[p_name] = v.value
                    
            return export_data
        finally:
            db.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/save")
def api_save_payload(req: SavePayloadRequest):
    """Saves analysis payload as [host_name]_analysis.json."""
    try:
        pydantic_payload = HostAnalysisPayload(**req.payload)
        saved_file = ZabbixAnalyzer.save_analysis_json(pydantic_payload, output_dir=req.output_dir or ".")
        return {"success": True, "file_path": saved_file}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/", response_class=HTMLResponse)
def get_index():
    """Serves the main Web Dashboard interface."""
    template_path = Path(__file__).parent / "templates" / "index.html"
    if template_path.exists():
        return HTMLResponse(content=template_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>JASS UI Template Not Found</h1>", status_code=404)

@app.get("/admin", response_class=HTMLResponse)
def get_admin():
    """Serves the Admin Configuration interface."""
    template_path = Path(__file__).parent / "templates" / "admin.html"
    if template_path.exists():
        return HTMLResponse(content=template_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>JASS Admin Template Not Found</h1>", status_code=404)


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

