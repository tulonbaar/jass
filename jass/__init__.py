"""
JASS - Just Another System Sniffer
Advanced telemetry framework for Windows and Hyper-V integrating with Zabbix API
for automated infrastructure and business role analysis via LLMs.
"""

import os

# Best-effort loading of .env file
try:
    from dotenv import load_dotenv
    # Force override OS environment variables with .env values
    load_dotenv(override=True)
except ImportError:
    pass

# Fallback parser that also forces override
env_path = os.path.join(os.getcwd(), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("\"'")
                os.environ[key] = value

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
