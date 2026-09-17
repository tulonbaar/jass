from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
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


class ProberParser(Base):
    """Definicje parserów parsujących output z Probera."""
    __tablename__ = "prober_parsers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    parser_type = Column(String)  # np. 'regex', 'python'
    code = Column(Text)  # Kod Pythona lub wyrażenie regularne
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relacja odwrotna
    scripts = relationship("ProberScript", back_populates="default_parser")


class ProberScript(Base):
    """Skrypty PowerShell wysyłane jako payload do Probera."""
    __tablename__ = "prober_scripts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    content = Column(Text)  # Kod źródłowy PowerShell
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Opcjonalny domyślny parser dla tego skryptu
    default_parser_id = Column(Integer, ForeignKey("prober_parsers.id"), nullable=True)
    default_parser = relationship("ProberParser", back_populates="scripts")


class ProberHostConfig(Base):
    """Konfiguracja Probera per Host (nadpisuje domyślne ustawienia z env)."""
    __tablename__ = "prober_host_configs"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(String, unique=True, index=True) # Powiązanie z host.hostid z Zabbixa
    port = Column(Integer, default=8443)
    ttl_seconds = Column(Integer, default=3600)  # Czas życia efemerycznego agenta (np. 1 godzina)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
