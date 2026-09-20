from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional, Any, Dict
from jass.db.database import get_db
from sqlalchemy.orm import Session
from jass.db.models import ZabbixScript, ProberParser

router = APIRouter(prefix="/api/zabbix-scripts", tags=["zabbix-scripts"])

class ZabbixScriptCreate(BaseModel):
    name: str
    description: Optional[str] = None
    script_type: int = 0
    execute_on: int = 1
    command: Optional[str] = ""
    scope: int = 2
    url: Optional[str] = ""
    timeout: Optional[str] = "30s"
    parameters: Optional[List[Dict[str, str]]] = []
    username: Optional[str] = None
    password: Optional[str] = None
    port: Optional[str] = None
    map_to_properties: bool = True
    parser_id: Optional[int] = None

class ZabbixScriptUpdate(ZabbixScriptCreate):
    pass

class ZabbixScriptResponse(ZabbixScriptCreate):
    id: int
    
    class Config:
        orm_mode = True
        from_attributes = True

@router.get("", response_model=List[ZabbixScriptResponse])
def get_scripts(db: Session = Depends(get_db)):
    return db.query(ZabbixScript).all()

@router.post("", response_model=ZabbixScriptResponse)
def create_script(script: ZabbixScriptCreate, db: Session = Depends(get_db)):
    db_script = ZabbixScript(**script.model_dump())
    db.add(db_script)
    db.commit()
    db.refresh(db_script)
    return db_script

@router.put("/{script_id}", response_model=ZabbixScriptResponse)
def update_script(script_id: int, script: ZabbixScriptUpdate, db: Session = Depends(get_db)):
    db_script = db.query(ZabbixScript).filter(ZabbixScript.id == script_id).first()
    if not db_script:
        raise HTTPException(status_code=404, detail="Script not found")
    
    for key, value in script.model_dump().items():
        setattr(db_script, key, value)
    
    db.commit()
    db.refresh(db_script)
    return db_script

@router.delete("/{script_id}")
def delete_script(script_id: int, db: Session = Depends(get_db)):
    db_script = db.query(ZabbixScript).filter(ZabbixScript.id == script_id).first()
    if not db_script:
        raise HTTPException(status_code=404, detail="Script not found")
    db.delete(db_script)
    db.commit()
    return {"success": True}

class PushScriptRequest(BaseModel):
    script_id: int
    host_group_id: Optional[str] = None # '0' means all or specific

@router.post("/push-to-zabbix")
def push_script_to_zabbix(req: PushScriptRequest, db: Session = Depends(get_db)):
    db_script = db.query(ZabbixScript).filter(ZabbixScript.id == req.script_id).first()
    if not db_script:
        raise HTTPException(status_code=404, detail="Script not found")
        
    from jass.ui.app import get_or_create_analyzer
    analyzer = get_or_create_analyzer()
    client = analyzer.client
    
    # Check if script with this name already exists
    existing = client.call("script.get", {"filter": {"name": db_script.name}})
    
    script_params = {
        "name": db_script.name,
        "type": db_script.script_type,
        "description": db_script.description or "",
        "scope": db_script.scope,
    }
    
    # 0: Script, 1: IPMI, 2: Telnet, 3: SSH, 4: Global, 5: Webhook, URL? Wait, URL is type 6?
    # Actually Zabbix script types: 0=Script, 1=IPMI, 2=Telnet, 3=SSH, 4=Global, 5=Webhook, 6=URL (added in newer Zabbix versions?)
    if db_script.script_type in (0, 1, 2, 3):
        script_params["command"] = db_script.command or ""
    if db_script.script_type == 0:
        script_params["execute_on"] = db_script.execute_on
        
    if db_script.script_type in (2, 3): # SSH, Telnet
        script_params["username"] = db_script.username or ""
        script_params["password"] = db_script.password or ""
        if db_script.port:
            script_params["port"] = db_script.port
            
    if db_script.script_type == 5: # Webhook
        script_params["command"] = db_script.command or "" # Webhook script is in command field
        script_params["timeout"] = db_script.timeout or "30s"
        if db_script.parameters:
            script_params["parameters"] = db_script.parameters
            
    if db_script.script_type == 6: # URL
        script_params["url"] = db_script.url or ""
    if req.host_group_id:
        script_params["groupid"] = req.host_group_id
    else:
        script_params["groupid"] = "0"
        
    if db_script.script_type == 3: # SSH
        script_params["username"] = db_script.username or ""
        script_params["password"] = db_script.password or ""
        if db_script.port:
            script_params["port"] = db_script.port
            
    if existing:
        script_params["scriptid"] = existing[0]["scriptid"]
        res = client.call("script.update", script_params)
        return {"success": True, "message": "Updated existing script", "scriptids": res.get("scriptids", [])}
    else:
        res = client.call("script.create", script_params)
        return {"success": True, "message": "Created new script", "scriptids": res.get("scriptids", [])}



class ExecuteScriptRequest(BaseModel):
    script_id: int
    host_identifier: str # host_id or name

@router.post("/execute")
def execute_zabbix_script(req: ExecuteScriptRequest, db: Session = Depends(get_db)):
    db_script = db.query(ZabbixScript).filter(ZabbixScript.id == req.script_id).first()
    if not db_script:
        raise HTTPException(status_code=404, detail="Script not found")
        
    from jass.ui.app import get_or_create_analyzer
    analyzer = get_or_create_analyzer()
    client = analyzer.client
    
    # 1. Resolve host
    hosts = client.call("host.get", {"filter": {"host": req.host_identifier}, "output": ["hostid"]})
    if not hosts:
        hosts = client.call("host.get", {"filter": {"name": req.host_identifier}, "output": ["hostid"]})
        if not hosts:
            hosts = client.call("host.get", {"hostids": [req.host_identifier], "output": ["hostid"]})
            if not hosts:
                raise HTTPException(status_code=404, detail=f"Host {req.host_identifier} not found")
    host_id = hosts[0]["hostid"]
    
    # 2. Check if script exists in Zabbix
    z_scripts = client.call("script.get", {"filter": {"name": db_script.name}})
    if not z_scripts:
        raise HTTPException(status_code=404, detail=f"Script '{db_script.name}' not found on Zabbix Server. Push it first.")
        
    z_script_id = z_scripts[0]["scriptid"]
    
    # 3. Execute
    from jass.core.client import ZabbixAPIException
    try:
        res = client.call("script.execute", {"scriptid": z_script_id, "hostid": host_id})
    except ZabbixAPIException as ze:
        raise HTTPException(status_code=400, detail=f"Zabbix API Error: {ze.message}. This usually means the Zabbix Agent on the host is not configured to allow remote commands (EnableRemoteCommands=1) or the command is denied (AllowKey=system.run[*]).")
        
    if res.get("response") != "success":
        raise HTTPException(status_code=500, detail=res.get("info", "Unknown execution error"))
        
    output = res.get("value", "")
    parsed_output = None
    
    # 4. Parse if needed
    if db_script.parser_id:
        parser = db.query(ProberParser).filter(ProberParser.id == db_script.parser_id).first()
        if parser:
            try:
                local_env = {}
                exec(parser.code, local_env)
                if "parse" in local_env:
                    parsed_output = local_env["parse"](output)
            except Exception as e:
                parsed_output = {"error": f"Parser error: {str(e)}"}
                
    # 5. Save to properties if needed
    if db_script.map_to_properties and isinstance(parsed_output, dict) and "error" not in parsed_output:
        from jass.db.models import HostProperty, HostPropertyValue
        for prop_name, value in parsed_output.items():
            prop = db.query(HostProperty).filter_by(name=prop_name).first()
            if prop:
                val_record = db.query(HostPropertyValue).filter_by(host_id=host_id, property_id=prop.id).first()
                if not val_record:
                    val_record = HostPropertyValue(host_id=host_id, property_id=prop.id)
                    db.add(val_record)
                val_record.value = value
        db.commit()

    return {
        "success": True,
        "raw_output": output,
        "parsed_output": parsed_output
    }

