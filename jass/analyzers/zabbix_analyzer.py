"""
JASS - Just Another System Sniffer
Główny orkiestrator i analizator ZabbixAnalyzer
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from jass.core.client import ZabbixAPIException, ZabbixClient
from jass.core.models import HostAnalysisPayload
from jass.core.prompt_builder import LLMPromptBuilder
from jass.modules.windows_sniffer import WindowsSniffer

logger = logging.getLogger("jass.analyzers.zabbix")


class ZabbixAnalyzer:
    """
    Główna klasa analityczna frameworka JASS.
    Łączy komunikację z Zabbix API, moduły sniffingowe (Windows/Hyper-V) oraz eksport dla LLM.
    """

    def __init__(
        self,
        url: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 15,
        verify_ssl: bool = True,
    ) -> None:
        """
        Inicjalizacja ZabbixAnalyzer.

        :param url: URL instancji Zabbix (np. https://zabbix.corp.local)
        :param api_token: API Token (zalecany)
        :param username: Login użytkownika Zabbix (fallback)
        :param password: Hasło użytkownika Zabbix (fallback)
        :param timeout: Timeout zapytań HTTP
        :param verify_ssl: Weryfikacja certyfikatów SSL
        """
        self.client = ZabbixClient(
            url=url,
            api_token=api_token,
            username=username,
            password=password,
            timeout=timeout,
            verify_ssl=verify_ssl,
        )
        # Rejestr modułów analizujących
        self.windows_sniffer = WindowsSniffer(self.client)
        self._connected = False

    def connect(self) -> str:
        """Nawiązuje połączenie z Zabbix API."""
        version = self.client.connect()
        self._connected = True
        return version

    def list_hostgroups(self) -> List[Dict[str, Any]]:
        """
        Pobiera listę grup hostów z Zabbix API (hostgroup.get).
        """
        if not self._connected:
            self.connect()
        logger.debug("Pobieranie listy grup hostów (hostgroup.get)...")
        res = self.client.call("hostgroup.get", {"output": ["groupid", "name"]})
        return sorted(res, key=lambda x: x.get("name", ""))

    def list_hosts(
        self,
        group_ids: Optional[List[str]] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Pobiera listę hostów z opcjonalnym filtrowaniem po grupie lub nazwie (host.get).
        """
        if not self._connected:
            self.connect()

        params: Dict[str, Any] = {
            "output": ["hostid", "host", "name", "status", "description"],
            "selectInterfaces": ["ip", "dns"],
            "selectGroups": ["groupid", "name"],
        }
        if group_ids:
            params["groupids"] = group_ids
        if search:
            params["search"] = {"host": search, "name": search}
            params["searchByAny"] = True

        res = self.client.call("host.get", params)
        return sorted(res, key=lambda x: x.get("name", ""))

    def analyze_host(
        self,
        host_identifier: str,
        run_remote_probe: bool = False,
        script_name: Optional[str] = None,
    ) -> HostAnalysisPayload:
        """
        Przeprowadza pełną analizę pojedynczego hosta.

        :param host_identifier: Nazwa techniczna hosta, widoczna nazwa lub hostid
        :param run_remote_probe: Czy uruchomić zdalną sondę przez script.execute
        :param script_name: Nazwa predefiniowanego skryptu w Zabbixie
        :return: Ustrukturyzowany obiekt HostAnalysisPayload
        """
        if not self._connected:
            self.connect()

        # Na ten moment używamy WindowsSniffer (z możliwością automatycznej detekcji OS w przyszłości)
        payload = self.windows_sniffer.analyze_host(
            host_identifier=host_identifier,
            run_remote_probe=run_remote_probe,
            script_name=script_name,
        )
        return payload

    def analyze_hostgroup(
        self,
        group_identifier: str,
        run_remote_probe: bool = False,
        script_name: Optional[str] = None,
    ) -> List[HostAnalysisPayload]:
        """
        Przeprowadza analizę wszystkich hostów w wybranej grupie.

        :param group_identifier: Nazwa grupy lub groupid
        :param run_remote_probe: Czy wykonywać zdalne sondy na każdym hoście
        :param script_name: Nazwa skryptu
        :return: Lista obiektów HostAnalysisPayload
        """
        if not self._connected:
            self.connect()

        logger.info(f"Wyszukiwanie grupy hostów '{group_identifier}'...")
        # Wyszukanie grupy
        group_params: Dict[str, Any] = {"output": ["groupid", "name"]}
        if group_identifier.isdigit():
            group_params["groupids"] = [group_identifier]
        else:
            group_params["filter"] = {"name": [group_identifier]}

        groups = self.client.call("hostgroup.get", group_params)
        if not groups:
            # Próba elastycznego wyszukania grupy
            groups = self.client.call("hostgroup.get", {"output": ["groupid", "name"], "search": {"name": group_identifier}})

        if not groups:
            raise ZabbixAPIException(f"Nie odnaleziono grupy hostów '{group_identifier}' w systemie Zabbix.")

        group = groups[0]
        group_id = group["groupid"]
        group_name = group["name"]
        logger.info(f"Odnaleziono grupę: {group_name} (ID: {group_id}). Pobieranie hostów...")

        hosts = self.list_hosts(group_ids=[group_id])
        logger.info(f"Liczba hostów w grupie: {len(hosts)}")

        results: List[HostAnalysisPayload] = []
        for h in hosts:
            h_name = h.get("host") or h.get("name") or h["hostid"]
            try:
                payload = self.analyze_host(h_name, run_remote_probe=run_remote_probe, script_name=script_name)
                results.append(payload)
            except Exception as e:
                logger.error(f"Błąd podczas analizy hosta {h_name}: {e}")

        return results

    @staticmethod
    def save_analysis_json(payload: HostAnalysisPayload, output_dir: Union[str, Path] = ".") -> str:
        """
        Zapisuje ustrukturyzowany plik JSON jako [nazwa_hosta]_analysis.json.

        :param payload: Dane analizy hosta
        :param output_dir: Katalog docelowy
        :return: Ścieżka do zapisanego pliku
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Bezpieczna nazwa pliku (usunięcie znaków niedozwolonych)
        safe_name = "".join(c for c in payload.host_name if c.isalnum() or c in ("-", "_", ".")).rstrip()
        if not safe_name:
            safe_name = f"host_{payload.host_id}"

        file_name = f"{safe_name}_analysis.json"
        full_path = out_path / file_name

        json_content = payload.to_llm_json(indent=2)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(json_content)

        logger.info(f"Zapisano plik analizy: {full_path.resolve()}")
        return str(full_path.resolve())

    def save_group_analysis_json(self, payloads: List[HostAnalysisPayload], output_dir: Union[str, Path] = ".") -> List[str]:
        """Zapisuje analizy dla całej grupy maszyn."""
        saved_paths: List[str] = []
        for p in payloads:
            path = self.save_analysis_json(p, output_dir=output_dir)
            saved_paths.append(path)
        return saved_paths

    @staticmethod
    def generate_llm_prompt(payload: HostAnalysisPayload) -> str:
        """Generuje gotowy prompt LLM dla danego hosta."""
        return LLMPromptBuilder.build_user_prompt(payload)

    def close(self) -> None:
        """Zamyka sesję klienta."""
        if self._connected:
            self.client.logout()
            self._connected = False

    def __enter__(self) -> "ZabbixAnalyzer":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
