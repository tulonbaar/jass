from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from jass.db.database import Base
from datetime import datetime

class PropertyCategory(Base):
    """Kategorie grupujące właściwości hosta (np. Overview, Disks, Apps)."""
    __tablename__ = "property_categories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    display_name = Column(String)
    order = Column(Integer, default=0)
    icon = Column(String, default="fa-folder")

    properties = relationship("HostProperty", back_populates="category", cascade="all, delete-orphan")


class HostProperty(Base):
    """Definicja właściwości hosta."""
    __tablename__ = "host_properties"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)  # np. 'listening_ports', 'os_version'
    display_name = Column(String)
    description = Column(String, nullable=True)
    data_type = Column(String, default="string") # string, number, boolean, json, list
    display_mode = Column(String, default="auto") # auto, table, key_value, badge, json
    
    category_id = Column(Integer, ForeignKey("property_categories.id"))
    category = relationship("PropertyCategory", back_populates="properties")

    values = relationship("HostPropertyValue", back_populates="property", cascade="all, delete-orphan")
    metric_mappings = relationship("ZabbixMetricMapping", back_populates="property", cascade="all, delete-orphan")


class HostPropertyValue(Base):
    """Konkretna wartość właściwości przypisana do hosta."""
    __tablename__ = "host_property_values"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(String, index=True) # Powiązanie z host.hostid z Zabbixa
    property_id = Column(Integer, ForeignKey("host_properties.id"))
    
    # Dane zachowujemy jako JSON, z którego UI odczyta wartość zgodnie z type
    value = Column(JSON, nullable=True)
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    property = relationship("HostProperty", back_populates="values")


class ZabbixMetricMapping(Base):
    """Mapowanie metryk pobieranych z Zabbix na HostProperty."""
    __tablename__ = "zabbix_metric_mappings"

    id = Column(Integer, primary_key=True, index=True)
    zabbix_item_key = Column(String, index=True) # np. 'system.cpu.util'
    property_id = Column(Integer, ForeignKey("host_properties.id"))
    
    property = relationship("HostProperty", back_populates="metric_mappings")


class ProberParser(Base):
    """Definicje parserów parsujących output z Probera."""
    __tablename__ = "prober_parsers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    
    # Kod Pythona w którym musi być funkcja `def parse(output): return dict(...)`
    code = Column(Text)  
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tasks = relationship("ProberTask", back_populates="parser")


class ProberTask(Base):
    """Zadania (skrypty) wysyłane jako payload do Probera."""
    __tablename__ = "prober_tasks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    script_type = Column(String, default="powershell") # powershell, cmd, bash
    content = Column(Text)  # Kod źródłowy
    
    # Czy wynik powinien być mapowany na właściwości hosta?
    map_to_properties = Column(Boolean, default=True)

    parser_id = Column(Integer, ForeignKey("prober_parsers.id"), nullable=True)
    parser = relationship("ProberParser", back_populates="tasks")

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ProberHostConfig(Base):
    """Konfiguracja Probera per Host (nadpisuje domyślne ustawienia z env)."""
    __tablename__ = "prober_host_configs"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(String, unique=True, index=True) # Powiązanie z host.hostid z Zabbixa
    port = Column(Integer, default=10052)
    psk = Column(String) # Losowy PSK wygenerowany do połączenia
    ttl_seconds = Column(Integer, default=3600)  # Czas życia efemerycznego agenta (np. 1 godzina)
    is_active = Column(Boolean, default=False)
    last_launched = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SystemSetting(Base):
    """Tabela przechowująca globalne ustawienia aplikacji w formacie klucz-wartość."""
    __tablename__ = "system_settings"

    key = Column(String, primary_key=True, index=True)
    value = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ZabbixHostGroup(Base):
    """Pobrane z Zabbix API grupy hostów."""
    __tablename__ = "zabbix_host_groups"
    
    id = Column(Integer, primary_key=True, index=True)
    groupid = Column(String, unique=True, index=True)
    name = Column(String)

class ZabbixScript(Base):
    """Zadania (skrypty) wysyłane do Zabbix jako Zabbix Scripts."""
    __tablename__ = "zabbix_scripts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True) 
    description = Column(String, nullable=True)
    
    script_type = Column(Integer, default=0) # 0: Script, 1: IPMI, 2: Telnet, 3: SSH, 4: Global script, 5: Webhook
    execute_on = Column(Integer, default=1) # 0: agent, 1: server, 2: server (proxy)
    command = Column(Text)  
    
    scope = Column(Integer, default=2) # 1: Action, 2: Manual host, 4: Manual event
    url = Column(String, nullable=True) # for URL
    timeout = Column(String, default="30s") # for Webhook
    parameters = Column(JSON, nullable=True) # for Webhook
    
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    port = Column(String, nullable=True)
    
    map_to_properties = Column(Boolean, default=True)

    parser_id = Column(Integer, ForeignKey("prober_parsers.id"), nullable=True)
    parser = relationship("ProberParser", foreign_keys=[parser_id])

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
