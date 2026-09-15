"""
JASS - Just Another System Sniffer
Klasa bazowa dla modułów sniffera (ekspandowalność na inne systemy)
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
    Abstrakcyjna klasa bazowa dla modułów zbierających dane systemowe.
    Pozwala na łatwe dodawanie kolejnych systemów (np. Linux, VMware ESXi, Network Appliances).
    """

    def __init__(self, client: ZabbixClient) -> None:
        self.client = client

    @property
    @abstractmethod
    def module_name(self) -> str:
        """Nazwa modułu sniffera."""
        pass

    @property
    @abstractmethod
    def target_platform(self) -> str:
        """Docelowa platforma (np. 'Windows', 'Linux', 'Network')."""
        pass

    @abstractmethod
    def collect_inventory(self, host_id: str, host_raw: Dict[str, Any]) -> HostInventory:
        """Pobranie i przetworzenie sekcji Host Inventory."""
        pass

    @abstractmethod
    def collect_metrics(self, host_id: str) -> HostMetrics:
        """Pobranie i przetworzenie kluczowych metryk (CPU, RAM, Dysk, Uptime)."""
        pass

    @abstractmethod
    def collect_services(self, host_id: str) -> List[WindowsService]:
        """Pobranie statusów usług systemowych."""
        pass

    @abstractmethod
    def collect_virtualization_data(self, host_id: str) -> HyperVData:
        """Pobranie danych o wirtualizacji (np. Hyper-V)."""
        pass

    @abstractmethod
    def execute_remote_probe(self, host_id: str, script_name_or_cmd: Optional[str] = None) -> Optional[RemoteExecutionResult]:
        """Wykonanie zdalnego skryptu/sondy na agencie przez Zabbix API."""
        pass

    @abstractmethod
    def analyze_host(self, host_identifier: str, run_remote_probe: bool = False) -> HostAnalysisPayload:
        """Przeprowadzenie pełnego badania hosta i wygenerowanie ustrukturyzowanego payloadu."""
        pass
