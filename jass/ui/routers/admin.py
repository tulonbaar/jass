import os
from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from jass.db.database import get_db
from sqlalchemy.orm import Session
from jass.db.models import PropertyCategory, HostProperty, ProberTask, ProberParser

router = APIRouter(prefix="/api/admin", tags=["Admin"])

# Models for CRUD
class CategoryCreate(BaseModel):
    name: str
    display_name: str
    order: int = 0
    icon: Optional[str] = "fa-folder"
    property_ids: Optional[List[int]] = []

class PropertyCreate(BaseModel):
    name: str
    display_name: str
    description: Optional[str] = None
    data_type: str = "string"
    display_mode: Optional[str] = "auto"
    category_id: int
    zabbix_mapping: Optional[str] = None

class TaskCreate(BaseModel):
    name: str
    description: Optional[str] = None
    script_type: str = "powershell"
    content: str
    map_to_properties: bool = True
    parser_id: Optional[int] = None

class ParserCreate(BaseModel):
    name: str
    description: Optional[str] = None
    code: str

@router.get("/categories")
def get_categories(db: Session = Depends(get_db)):
    cats = db.query(PropertyCategory).order_by(PropertyCategory.order).all()
    return cats

@router.post("/categories")
def create_category(cat: CategoryCreate, db: Session = Depends(get_db)):
    data = cat.model_dump()
    prop_ids = data.pop("property_ids", [])
    obj = PropertyCategory(**data)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    if prop_ids:
        db.query(HostProperty).filter(HostProperty.id.in_(prop_ids)).update({"category_id": obj.id}, synchronize_session=False)
        db.commit()
    return obj

@router.get("/properties")
def get_properties(db: Session = Depends(get_db)):
    props = db.query(HostProperty).all()
    from jass.db.models import ZabbixMetricMapping
    res = []
    for p in props:
        d = {
            "id": p.id, "name": p.name, "display_name": p.display_name,
            "description": p.description, "data_type": p.data_type,
            "display_mode": p.display_mode, "category_id": p.category_id,
            "zabbix_mapping": None
        }
        zm = db.query(ZabbixMetricMapping).filter_by(property_id=p.id).first()
        if zm:
            d["zabbix_mapping"] = zm.zabbix_item_key
        res.append(d)
    return res

@router.post("/properties")
def create_property(prop: PropertyCreate, db: Session = Depends(get_db)):
    from jass.db.models import ZabbixMetricMapping
    data = prop.model_dump()
    z_map = data.pop("zabbix_mapping", None)
    obj = HostProperty(**data)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    if z_map:
        zm = ZabbixMetricMapping(zabbix_item_key=z_map, property_id=obj.id)
        db.add(zm)
        db.commit()
    return obj

@router.get("/tasks")
def get_tasks(db: Session = Depends(get_db)):
    return db.query(ProberTask).all()

@router.post("/tasks")
def create_task(task: TaskCreate, db: Session = Depends(get_db)):
    obj = ProberTask(**task.model_dump())
    db.add(obj)
    db.commit()
    return obj

@router.get("/parsers")
def get_parsers(db: Session = Depends(get_db)):
    return db.query(ProberParser).all()

@router.post("/parsers")
def create_parser(parser: ParserCreate, db: Session = Depends(get_db)):
    obj = ProberParser(**parser.model_dump())
    db.add(obj)
    db.commit()
    return obj

@router.delete("/categories/{id}")
def delete_category(id: int, db: Session = Depends(get_db)):
    obj = db.get(PropertyCategory, id)
    if obj:
        db.delete(obj)
        db.commit()
    return {"success": True}

@router.put("/categories/{id}")
def update_category(id: int, cat: CategoryCreate, db: Session = Depends(get_db)):
    obj = db.get(PropertyCategory, id)
    if not obj: raise HTTPException(404)
    data = cat.model_dump()
    prop_ids = data.pop("property_ids", None)
    for key, val in data.items():
        setattr(obj, key, val)
    if prop_ids is not None:
        db.query(HostProperty).filter(HostProperty.category_id == id).update({"category_id": None}, synchronize_session=False)
        if prop_ids:
            db.query(HostProperty).filter(HostProperty.id.in_(prop_ids)).update({"category_id": id}, synchronize_session=False)
    db.commit()
    db.refresh(obj)
    return obj

@router.delete("/properties/{id}")
def delete_property(id: int, db: Session = Depends(get_db)):
    obj = db.get(HostProperty, id)
    if obj:
        db.delete(obj)
        db.commit()
    return {"success": True}

@router.put("/properties/{id}")
def update_property(id: int, prop: PropertyCreate, db: Session = Depends(get_db)):
    from jass.db.models import ZabbixMetricMapping
    obj = db.get(HostProperty, id)
    if not obj: raise HTTPException(404)
    data = prop.model_dump()
    z_map = data.pop("zabbix_mapping", None)
    for key, val in data.items():
        setattr(obj, key, val)
        
    zm = db.query(ZabbixMetricMapping).filter_by(property_id=obj.id).first()
    if z_map:
        if zm:
            zm.zabbix_item_key = z_map
        else:
            zm = ZabbixMetricMapping(zabbix_item_key=z_map, property_id=obj.id)
            db.add(zm)
    else:
        if zm:
            db.delete(zm)
            
    db.commit()
    return obj

@router.delete("/tasks/{id}")
def delete_task(id: int, db: Session = Depends(get_db)):
    obj = db.get(ProberTask, id)
    if obj:
        db.delete(obj)
        db.commit()
    return {"success": True}

@router.put("/tasks/{id}")
def update_task(id: int, task: TaskCreate, db: Session = Depends(get_db)):
    obj = db.get(ProberTask, id)
    if not obj: raise HTTPException(404)
    for key, val in task.model_dump().items():
        setattr(obj, key, val)
    db.commit()
    return obj

@router.delete("/parsers/{id}")
def delete_parser(id: int, db: Session = Depends(get_db)):
    obj = db.get(ProberParser, id)
    if obj:
        db.delete(obj)
        db.commit()
    return {"success": True}

@router.put("/parsers/{id}")
def update_parser(id: int, parser: ParserCreate, db: Session = Depends(get_db)):
    obj = db.get(ProberParser, id)
    if not obj: raise HTTPException(404)
    for key, val in parser.model_dump().items():
        setattr(obj, key, val)
    db.commit()
    return obj


class AppSettings(BaseModel):
    zabbix_url: str = ""
    zabbix_api_token: str = ""
    zabbix_user: str = ""
    zabbix_password: str = ""
    zabbix_timeout: int = 15
    zabbix_verify_ssl: bool = True
    zabbix_host_groups: str = ""
    prober_default_port: int = 10052
    prober_default_ttl: int = 1800
    prober_execution_timeout: int = 600
    log_level: str = "INFO"

@router.get("/settings", response_model=AppSettings)
def get_settings():
    from jass.core.settings import get_setting
    return AppSettings(
        zabbix_url=get_setting("ZABBIX_URL", ""),
        zabbix_api_token=get_setting("ZABBIX_API_TOKEN", ""),
        zabbix_user=get_setting("ZABBIX_USER", ""),
        zabbix_password=get_setting("ZABBIX_PASSWORD", ""),
        zabbix_timeout=int(get_setting("ZABBIX_TIMEOUT", 15)),
        zabbix_verify_ssl=get_setting("ZABBIX_VERIFY_SSL", "true").lower() == "true",
        zabbix_host_groups=get_setting("zabbix_host_groups", ""),
        prober_default_port=int(get_setting("PROBER_DEFAULT_PORT", 10052)),
        prober_default_ttl=int(get_setting("PROBER_DEFAULT_TTL", 1800)),
        prober_execution_timeout=int(get_setting("PROBER_EXECUTION_TIMEOUT", 600)),
        log_level=get_setting("LOG_LEVEL", "INFO")
    )

@router.post("/settings")
def update_settings(settings: AppSettings):
    from jass.core.settings import set_setting
    
    set_setting("ZABBIX_URL", settings.zabbix_url)
    set_setting("ZABBIX_API_TOKEN", settings.zabbix_api_token)
    set_setting("ZABBIX_USER", settings.zabbix_user)
    set_setting("ZABBIX_PASSWORD", settings.zabbix_password)
    set_setting("ZABBIX_TIMEOUT", str(settings.zabbix_timeout))
    set_setting("ZABBIX_VERIFY_SSL", "true" if settings.zabbix_verify_ssl else "false")
    set_setting("zabbix_host_groups", settings.zabbix_host_groups)
    
    set_setting("PROBER_DEFAULT_PORT", str(settings.prober_default_port))
    set_setting("PROBER_DEFAULT_TTL", str(max(1800, settings.prober_default_ttl)))
    set_setting("PROBER_EXECUTION_TIMEOUT", str(settings.prober_execution_timeout))
    set_setting("LOG_LEVEL", settings.log_level)
    

    # Update logger dynamically
    import logging
    numeric_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.getLogger().setLevel(numeric_level)
    logging.getLogger("jass").setLevel(numeric_level)
    
    # Reload analyzer if needed
    import jass.ui.app as main_app
    main_app.state["zabbix_url"] = settings.zabbix_url
    main_app.state["api_token"] = settings.zabbix_api_token
    main_app.state["username"] = settings.zabbix_user
    main_app.state["password"] = settings.zabbix_password
    main_app.state["verify_ssl"] = settings.zabbix_verify_ssl
    main_app.state["analyzer"] = None # Force re-init on next use
    
    return {"success": True}
