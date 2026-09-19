from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from jass.db.database import get_db
from jass.db.models import HostPropertyValue, PropertyCategory, HostProperty
from typing import Any, Dict, List

router = APIRouter(prefix="/api/host-properties", tags=["Host Properties"])

@router.get("/{host_id}")
def get_host_properties(host_id: str, db: Session = Depends(get_db)):
    """Returns all properties for a host, grouped by category."""
    
    # 1. Get all categories
    categories = db.query(PropertyCategory).order_by(PropertyCategory.order).all()
    
    # 2. Get all property definitions
    props = db.query(HostProperty).all()
    prop_map = {p.id: p for p in props}
    
    # 3. Get actual values for this host
    values = db.query(HostPropertyValue).filter(HostPropertyValue.host_id == host_id).all()
    val_map = {v.property_id: v.value for v in values}
    
    result = []
    for cat in categories:
        cat_props = []
        for p in props:
            if p.category_id == cat.id:
                val = val_map.get(p.id)
                cat_props.append({
                    "id": p.id,
                    "name": p.name,
                    "display_name": p.display_name,
                    "description": p.description,
                    "data_type": p.data_type,
                    "display_mode": getattr(p, "display_mode", "auto") or "auto",
                    "value": val
                })
        
        result.append({
            "id": cat.id,
            "name": cat.name,
            "display_name": cat.display_name,
            "order": cat.order,
            "icon": getattr(cat, "icon", "fa-folder") or "fa-folder",
            "properties": cat_props
        })
        
    return {"categories": result}

