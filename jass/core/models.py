"""
JASS - Just Another System Sniffer
Data structure models for collected telemetry from monitored systems
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HostInterface(BaseModel):
    """Host network / agent interface information."""
    interfaceid: str
    ip: str
    dns: str
    port: str
    type: int  # 1: Agent, 2: SNMP, 3: IPMI, 4: JMX
    main: int  # 1: Default, 0: Secondary
    mac: Optional[str] = None


class HostTag(BaseModel):
    """Zabbix host tag."""
    tag: str
    value: str


class HostInventory(BaseModel):
    """Structured inventory data (Zabbix Host Inventory)."""
    os: Optional[str] = None
    os_full: Optional[str] = None
    os_short: Optional[str] = None
    hardware: Optional[str] = None
    hardware_full: Optional[str] = None
    serial_number: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    mac_addresses: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    location: Optional[str] = None
    contact: Optional[str] = None
    notes: Optional[str] = None
    raw_inventory: Dict[str, Any] = Field(default_factory=dict)


class DriveMetric(BaseModel):
    """Capacity and utilization metrics for a single storage drive/volume."""
    fs_name: str  # e.g., C:, D:
    total_bytes: Optional[int] = None
    total_formatted: Optional[str] = None
    used_bytes: Optional[int] = None
    used_formatted: Optional[str] = None
    free_bytes: Optional[int] = None
    free_formatted: Optional[str] = None
    used_percent: Optional[float] = None
    free_percent: Optional[float] = None


class HostMetrics(BaseModel):
    """Key performance and capacity metrics of the host."""
    cpu_utilization_percent: Optional[float] = None
    cpu_cores: Optional[int] = None
    memory_total_bytes: Optional[int] = None
    memory_total_formatted: Optional[str] = None
    memory_used_bytes: Optional[int] = None
    memory_used_formatted: Optional[str] = None
    memory_free_bytes: Optional[int] = None
    memory_free_formatted: Optional[str] = None
    memory_utilization_percent: Optional[float] = None
    uptime_seconds: Optional[int] = None
    uptime_formatted: Optional[str] = None
    drives: List[DriveMetric] = Field(default_factory=list)
    raw_items_sample: Dict[str, Any] = Field(default_factory=dict)


class WindowsService(BaseModel):
    """Status of a monitored Windows system service."""
    name: str
    display_name: Optional[str] = None
    state: str  # Running, Stopped, Paused, Unknown
    startup_type: Optional[str] = None  # Automatic, Manual, Disabled
    item_key: Optional[str] = None
    raw_value: Optional[str] = None


class HyperVGuestVM(BaseModel):
    """Information regarding a virtual machine guest running on Hyper-V."""
    vm_name: str
    state: str  # Running, Off, Saved, Paused, Unknown
    cpu_cores: Optional[int] = None
    memory_allocated_formatted: Optional[str] = None
    health: Optional[str] = None
    uptime: Optional[str] = None
    raw_attributes: Dict[str, Any] = Field(default_factory=dict)


class HyperVData(BaseModel):
    """Hyper-V telemetry data collected from host."""
    is_hyperv_host: bool = False
    hypervisor_version: Optional[str] = None
    virtual_machines_count: int = 0
    guest_vms: List[HyperVGuestVM] = Field(default_factory=list)
    raw_hyperv_metrics: Dict[str, Any] = Field(default_factory=dict)


class RemoteExecutionResult(BaseModel):
    """Result of remote script execution via Zabbix API (script.execute)."""
    script_name: str
    command: Optional[str] = None
    executed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    success: bool = True
    exit_code: Optional[int] = None
    raw_output: str = ""
    parsed_listening_ports: List[Dict[str, Any]] = Field(default_factory=list)
    error_message: Optional[str] = None


class HostAnalysisPayload(BaseModel):
    """
    Complete structured data payload collected from a host, formatted as an LLM ingestion payload.
    """
    schema_version: str = "1.0.0"
    collector: str = "JASS - Just Another System Sniffer (Windows/Hyper-V Analyzer)"
    collected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    # Host Identification
    host_id: str
    host_name: str
    visible_name: str
    status: str  # Monitored, Unmonitored
    host_groups: List[str] = Field(default_factory=list)
    tags: List[HostTag] = Field(default_factory=list)
    interfaces: List[HostInterface] = Field(default_factory=list)
    
    # Data Modules
    inventory: HostInventory = Field(default_factory=HostInventory)
    metrics: HostMetrics = Field(default_factory=HostMetrics)
    windows_services: List[WindowsService] = Field(default_factory=list)
    hyperv: HyperVData = Field(default_factory=HyperVData)
    remote_execution: Optional[RemoteExecutionResult] = None
    
    # LLM Context Hints & Signatures
    llm_context_hints: Dict[str, Any] = Field(default_factory=dict)

    def to_llm_json(self, indent: int = 2) -> str:
        """Returns a clean, nested JSON string ready for LLM consumption."""
        return self.model_dump_json(indent=indent)
