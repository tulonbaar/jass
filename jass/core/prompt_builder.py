"""
JASS - Just Another System Sniffer
Prompt generator for LLM models (OpenAI, Claude, Ollama, DeepSeek, etc.)
"""

from __future__ import annotations

import json
from typing import Dict, Any, Optional
from jass.core.models import HostAnalysisPayload


class LLMPromptBuilder:
    """
    Prompt compiler for Large Language Models (LLMs).
    Formulates precise context and instructions for LLMs to analyze the business purpose of a host.
    """

    SYSTEM_PROMPT = """You are a Senior Enterprise Infrastructure Architect and an expert in Windows Server / Hyper-V ecosystems.
Your task is to analyze structured telemetry and inventory data originating from a Zabbix monitoring system (JASS Telemetry Payload) for a target server.

Based on the provided metrics, running/installed Windows services, storage drives, Hyper-V roles, listening ports, and host inventory, generate a comprehensive Markdown report covering:

1. 🎯 **Primary Business Role and Purpose** (e.g., Active Directory Domain Controller, MS SQL Server Database Engine, Hyper-V Hypervisor Cluster Node, IIS Web Application Server, File/Print Server, Exchange Mail Server, ERP/CRM backend, Backup Repository, etc.).
2. 🧩 **Detected Technology Stack & Key Components** (detected software, database engines, frameworks, versions).
3. ⚡ **Resource Capacity & Sizing Assessment** (CPU, RAM, storage capacity, evaluating whether the machine is under stress or oversized).
4. 🛡️ **Security, Configuration & Exposure Insights** (listening network ports, OS lifecycle status, potential misconfigurations, unexpected background services).
5. 💡 **Architectural & Operational Recommendations** (suggested optimizations, maintenance, migration or backup improvements).
"""

    @classmethod
    def build_user_prompt(cls, payload: HostAnalysisPayload) -> str:
        """Constructs the user prompt containing the host telemetry JSON."""
        json_data = payload.to_llm_json(indent=2)
        
        prompt = f"""Below is the structured Zabbix telemetry data for host **{payload.host_name}** ({payload.visible_name}):

```json
{json_data}
```

Perform a comprehensive assessment of this server's business role, workload sizing, installed applications, and operational recommendations. Respond adhering to the system guidelines.
"""
        return prompt

    @classmethod
    def build_full_payload_for_api(cls, payload: HostAnalysisPayload, model: str = "gpt-4o") -> Dict[str, Any]:
        """
        Generates standard payload compatible with Chat Completions API (OpenAI / Anthropic / Ollama).
        """
        return {
            "model": model,
            "messages": [
                {"role": "system", "content": cls.SYSTEM_PROMPT},
                {"role": "user", "content": cls.build_user_prompt(payload)},
            ],
            "temperature": 0.2,
            "max_tokens": 4000,
        }
