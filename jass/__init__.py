"""
JASS - Just Another System Sniffer
Zaawansowany framework telemetryczny dla Windows i Hyper-V integrujący się z Zabbix API
pod kątem analizy przeznaczenia biznesowego przez modele LLM.
"""

__version__ = "1.0.0"
__author__ = "Senior DevOps Engineer"

from jass.analyzers.zabbix_analyzer import ZabbixAnalyzer
from jass.core.client import ZabbixAPIException, ZabbixAuthException, ZabbixClient
from jass.core.models import HostAnalysisPayload
from jass.core.prompt_builder import LLMPromptBuilder
from jass.modules.windows_sniffer import WindowsSniffer

__all__ = [
    "ZabbixClient",
    "ZabbixAPIException",
    "ZabbixAuthException",
    "ZabbixAnalyzer",
    "WindowsSniffer",
    "HostAnalysisPayload",
    "LLMPromptBuilder",
]
