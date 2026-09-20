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
    obj = PropertyCategory(**cat.model_dump())
    db.add(obj)
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
    for key, val in cat.model_dump().items():
        setattr(obj, key, val)
    db.commit()
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
