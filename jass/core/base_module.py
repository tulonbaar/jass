"""
JASS - Just Another System Sniffer
Base abstract class for system sniffer modules (extensible to other platforms)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from jass.core.client import ZabbixClient
from jass.core.models import (
    HostAnalysisPayload,
    HostInventory,
    HostMetrics,
    WindowsService,
    HyperVData,
    RemoteExecutionResult,
)


class BaseSystemSniffer(ABC):
    """
    Abstract base class for system sniffer modules.
    Allows easy extension for additional platforms (e.g., Linux, VMware ESXi, Network Appliances).
    """

    def __init__(self, client: ZabbixClient) -> None:
        self.client = client

    @property
    @abstractmethod
    def module_name(self) -> str:
        """Name of the sniffer module."""
        pass

    @property
    @abstractmethod
    def target_platform(self) -> str:
        """Target platform (e.g. 'Windows', 'Linux', 'Network')."""
        pass

    @abstractmethod
    def collect_inventory(self, host_id: str, host_raw: Dict[str, Any]) -> HostInventory:
        """Retrieve and process Host Inventory section."""
        pass

    @abstractmethod
    def collect_metrics(self, host_id: str) -> HostMetrics:
        """Retrieve and process key performance metrics (CPU, RAM, Disks, Uptime)."""
        pass

    @abstractmethod
    def collect_services(self, host_id: str) -> List[WindowsService]:
        """Retrieve system service statuses."""
        pass

    @abstractmethod
    def collect_virtualization_data(self, host_id: str) -> HyperVData:
        """Retrieve virtualization telemetry (e.g. Hyper-V)."""
        pass

    @abstractmethod
    def execute_remote_probe(self, host_id: str, script_name_or_cmd: Optional[str] = None) -> Optional[RemoteExecutionResult]:
        """Execute remote probe/script on agent via Zabbix API."""
        pass

    @abstractmethod
    def analyze_host(self, host_identifier: str, run_remote_probe: bool = False) -> HostAnalysisPayload:
        """Perform complete host audit and generate structured payload."""
        pass
