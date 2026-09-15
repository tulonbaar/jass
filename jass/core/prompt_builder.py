"""
JASS - Just Another System Sniffer
Generator promptów dla modeli LLM (OpenAI, Claude, Ollama, DeepSeek itp.)
"""

from __future__ import annotations

import json
from typing import Dict, Any, Optional
from jass.core.models import HostAnalysisPayload


class LLMPromptBuilder:
    """
    Kompilator promptów dla modeli językowych (LLM).
    Formułuje precyzyjny kontekst i instrukcje dla LLM w celu analizy roli biznesowej hosta.
    """

    SYSTEM_PROMPT = """Jesteś Senior Enterprise Architectem i ekspertem ds. infrastruktury Windows Server / Hyper-V.
Twoim zadaniem jest przeanalizowanie ustrukturyzowanych danych telemetrycznych i inwentarzowych pochodzących z systemu Zabbix (JASS Telemetry Payload) dla monitorowanego serwera.

Na podstawie przekazanych metryk, zainstalowanych/uruchomionych usług Windows, dysków, ról Hyper-V, otwartych portów oraz danych inwentaryzacyjnych przygotuj wyczerpujący raport w języku polskim w formacie Markdown zawierający:

1. 🎯 **Główna rola i przeznaczenie biznesowe serwera** (np. Active Directory Domain Controller, MS SQL Server Database Engine, Hyper-V Hypervisor Cluster Node, IIS Web Application Server, File/Print Server, Exchange/Mail, ERP/CRM backend, Backup Repository itp.).
2. 🧩 **Wykryty stos technologiczny i kluczowe komponenty** (wykryte aplikacje, bazy danych, technologie, wersje).
3. ⚡ **Ocena obciążenia i alokacji zasobów (Capacity & Sizing)** (CPU, RAM, przestrzeń dyskowa, czy maszyna jest przeciążona czy przewymiarowana).
4. 🛡️ **Wnioski dotyczące bezpieczeństwa i konfiguracji** (nasłuchujące porty, wersja OS, potencjalne ryzyka, usługi działające w tle).
5. 💡 **Rekomendacje architektoniczne i operacyjne** (np. sugerowane optymalizacje, planowane migracje, backupy).
"""

    @classmethod
    def build_user_prompt(cls, payload: HostAnalysisPayload) -> str:
        """Buduje prompt dla użytkownika zawierający JSON z danymi hosta."""
        json_data = payload.to_llm_json(indent=2)
        
        prompt = f"""Poniżej znajdują się ustrukturyzowane dane telemetryczne z systemu Zabbix dla hosta **{payload.host_name}** ({payload.visible_name}):

```json
{json_data}
```

Dokonaj szczegółowej analizy przeznaczenia biznesowego tego serwera, jego obciążenia, zainstalowanych aplikacji i rekomendacji. Odpowiedz zgodnie z wytycznymi systemowymi.
"""
        return prompt

    @classmethod
    def build_full_payload_for_api(cls, payload: HostAnalysisPayload, model: str = "gpt-4o") -> Dict[str, Any]:
        """
        Generuje standardowy payload zgodny z formatem Chat Completions API (OpenAI / Anthropic / Ollama).
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
