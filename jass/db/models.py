from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, JSON
from jass.db.database import Base
from datetime import datetime

class HostTelemetry(Base):
    """Stores the latest state of Zabbix resources for a host."""
    __tablename__ = "host_telemetry"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(String, unique=True, index=True)
    host_name = Column(String)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Store full JSON structure of HostAnalysisPayload
    # Because resources change fast, we overwrite the same row for host_id
    payload = Column(JSON)

class HostDiscovery(Base):
    """Stores historical discovery data (apps, ports, folders, logins) from Probes."""
    __tablename__ = "host_discoveries"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(String, index=True)
    probe_key = Column(String, index=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # The output JSON from the probe
    data = Column(JSON)
