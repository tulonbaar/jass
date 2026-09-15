"""
JASS - Just Another System Sniffer
Main ZabbixAnalyzer orchestrator
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
    Main analytical orchestrator for JASS.
    Connects Zabbix API communication, sniffing modules (Windows/Hyper-V), and LLM export.
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
        Initialize ZabbixAnalyzer.

        :param url: Zabbix instance URL (e.g. https://zabbix.corp.local)
        :param api_token: API Token (recommended)
        :param username: Zabbix username (fallback)
        :param password: Zabbix password (fallback)
        :param timeout: HTTP request timeout
        :param verify_ssl: SSL certificate verification
        """
        self.client = ZabbixClient(
            url=url,
            api_token=api_token,
            username=username,
            password=password,
            timeout=timeout,
            verify_ssl=verify_ssl,
        )
        # Sniffer modules registry
        self.windows_sniffer = WindowsSniffer(self.client)
        self._connected = False

    def connect(self) -> str:
        """Establishes connection to Zabbix API."""
        version = self.client.connect()
        self._connected = True
        return version

    def list_hostgroups(self) -> List[Dict[str, Any]]:
        """
        Retrieves list of host groups from Zabbix API (`hostgroup.get`).
        """
        if not self._connected:
            self.connect()
        logger.debug("Retrieving host groups (hostgroup.get)...")
        res = self.client.call("hostgroup.get", {"output": ["groupid", "name"]})
        return sorted(res, key=lambda x: x.get("name", ""))

    def list_hosts(
        self,
        group_ids: Optional[List[str]] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves list of hosts with optional filtering by group or search keyword (`host.get`).
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
        Performs full telemetry analysis on a single host.

        :param host_identifier: Technical host name, visible name, or hostid
        :param run_remote_probe: Whether to execute remote probe via script.execute
        :param script_name: Name of predefined Zabbix script
        :return: Structured HostAnalysisPayload object
        """
        if not self._connected:
            self.connect()

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
        Performs telemetry analysis on all hosts in the specified host group.

        :param group_identifier: Hostgroup name or groupid
        :param run_remote_probe: Whether to execute remote probe on each host
        :param script_name: Script name for remote probe
        :return: List of HostAnalysisPayload objects
        """
        if not self._connected:
            self.connect()

        logger.info(f"Searching for host group '{group_identifier}'...")
        group_params: Dict[str, Any] = {"output": ["groupid", "name"]}
        if group_identifier.isdigit():
            group_params["groupids"] = [group_identifier]
        else:
            group_params["filter"] = {"name": [group_identifier]}

        groups = self.client.call("hostgroup.get", group_params)
        if not groups:
            # Fuzzy match
            groups = self.client.call("hostgroup.get", {"output": ["groupid", "name"], "search": {"name": group_identifier}})

        if not groups:
            raise ZabbixAPIException(f"Host group '{group_identifier}' not found in Zabbix.")

        group = groups[0]
        group_id = group["groupid"]
        group_name = group["name"]
        logger.info(f"Found group: {group_name} (ID: {group_id}). Fetching hosts...")

        hosts = self.list_hosts(group_ids=[group_id])
        logger.info(f"Number of hosts in group: {len(hosts)}")

        results: List[HostAnalysisPayload] = []
        for h in hosts:
            h_name = h.get("host") or h.get("name") or h["hostid"]
            try:
                payload = self.analyze_host(h_name, run_remote_probe=run_remote_probe, script_name=script_name)
                results.append(payload)
            except Exception as e:
                logger.error(f"Error analyzing host {h_name}: {e}")

        return results

    @staticmethod
    def save_analysis_json(payload: HostAnalysisPayload, output_dir: Union[str, Path] = ".") -> str:
        """
        Saves structured JSON file as [host_name]_analysis.json.

        :param payload: Host analysis dataset
        :param output_dir: Target output directory
        :return: Absolute path to written file
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Sanitize filename
        safe_name = "".join(c for c in payload.host_name if c.isalnum() or c in ("-", "_", ".")).rstrip()
        if not safe_name:
            safe_name = f"host_{payload.host_id}"

        file_name = f"{safe_name}_analysis.json"
        full_path = out_path / file_name

        json_content = payload.to_llm_json(indent=2)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(json_content)

        logger.info(f"Saved analysis JSON: {full_path.resolve()}")
        return str(full_path.resolve())

    def save_group_analysis_json(self, payloads: List[HostAnalysisPayload], output_dir: Union[str, Path] = ".") -> List[str]:
        """Saves analysis files for all hosts in a group."""
        saved_paths: List[str] = []
        for p in payloads:
            path = self.save_analysis_json(p, output_dir=output_dir)
            saved_paths.append(path)
        return saved_paths

    @staticmethod
    def generate_llm_prompt(payload: HostAnalysisPayload) -> str:
        """Generates ready-to-use LLM prompt for the given host."""
        return LLMPromptBuilder.build_user_prompt(payload)

    def close(self) -> None:
        """Closes client session."""
        if self._connected:
            self.client.logout()
            self._connected = False

    def __enter__(self) -> "ZabbixAnalyzer":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
