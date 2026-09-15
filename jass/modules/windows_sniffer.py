"""
JASS - Just Another System Sniffer
Moduł Sniffera dla systemów Windows Server oraz Hyper-V
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from jass.core.base_module import BaseSystemSniffer
from jass.core.client import ZabbixAPIException, ZabbixClient
from jass.core.models import (
    DriveMetric,
    HostAnalysisPayload,
    HostInterface,
    HostInventory,
    HostMetrics,
    HostTag,
    HyperVData,
    HyperVGuestVM,
    RemoteExecutionResult,
    WindowsService,
)

logger = logging.getLogger("jass.modules.windows")


class WindowsSniffer(BaseSystemSniffer):
    """
    Dedykowany sniffer dla systemów z rodziny Microsoft Windows oraz roli Hyper-V.
    Zbiera inwentarz, telemetrię, statusy usług, maszyny wirtualne i wykonuje zdalne sondy przez Zabbix API.
    """

    SERVICE_STATES = {
        "0": "Running",
        "1": "Paused",
        "2": "Start pending",
        "3": "Pause pending",
        "4": "Continue pending",
        "5": "Stop pending",
        "6": "Stopped",
        "7": "Unknown",
    }

    SERVICE_STARTUP_TYPES = {
        "0": "Automatic",
        "1": "Automatic (delayed)",
        "2": "Manual",
        "3": "Disabled",
        "4": "Unknown",
    }

    @property
    def module_name(self) -> str:
        return "Windows & Hyper-V Deep Sniffer"

    @property
    def target_platform(self) -> str:
        return "Microsoft Windows / Hyper-V"

    @staticmethod
    def format_bytes(size_bytes: Optional[int]) -> Optional[str]:
        """Konwertuje bajty na czytelny format (B, KB, MB, GB, TB)."""
        if size_bytes is None:
            return None
        try:
            val = float(size_bytes)
        except (ValueError, TypeError):
            return None
        
        for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
            if abs(val) < 1024.0:
                return f"{val:.2f} {unit}"
            val /= 1024.0
        return f"{val:.2f} PB"

    @staticmethod
    def format_uptime(seconds: Optional[int]) -> Optional[str]:
        """Konwertuje sekundy uptime na czytelny format (dni, godziny, minuty)."""
        if seconds is None:
            return None
        try:
            s = int(seconds)
        except (ValueError, TypeError):
            return None
        
        days = s // 86400
        hours = (s % 86400) // 3600
        minutes = (s % 3600) // 60
        sec = s % 60
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0 or days > 0:
            parts.append(f"{hours}h")
        parts.append(f"{minutes}m {sec}s")
        return " ".join(parts)

    def fetch_host_details(self, host_identifier: str) -> Dict[str, Any]:
        """
        Pobiera podstawowe dane hosta z Zabbix API (metoda host.get).
        Obsługuje wyszukiwanie po host_name, visible_name lub hostid.
        """
        logger.debug(f"Pobieranie danych hosta '{host_identifier}' (host.get)...")
        
        params: Dict[str, Any] = {
            "output": ["hostid", "host", "name", "status", "description"],
            "selectInterfaces": ["interfaceid", "ip", "dns", "port", "type", "main"],
            "selectGroups": ["groupid", "name"],
            "selectTags": ["tag", "value"],
            "selectInventory": "extend",
        }

        # Jeśli identyfikator to cyfry, spróbujmy najpierw hostids
        if host_identifier.isdigit():
            params["hostids"] = [host_identifier]
            hosts = self.client.call("host.get", params)
            if hosts:
                return hosts[0]

        # Wyszukiwanie po nazwie technicznej hosta
        params_by_host = dict(params)
        params_by_host["filter"] = {"host": [host_identifier]}
        hosts = self.client.call("host.get", params_by_host)
        if hosts:
            return hosts[0]

        # Wyszukiwanie po widocznej nazwie (Visible name)
        params_by_name = dict(params)
        params_by_name["filter"] = {"name": [host_identifier]}
        hosts = self.client.call("host.get", params_by_name)
        if hosts:
            return hosts[0]

        # Wyszukiwanie elastyczne (search)
        params_search = dict(params)
        params_search["search"] = {"name": host_identifier, "host": host_identifier}
        params_search["searchByAny"] = True
        hosts = self.client.call("host.get", params_search)
        if hosts:
            return hosts[0]

        raise ZabbixAPIException(f"Nie odnaleziono hosta '{host_identifier}' w systemie Zabbix.")

    def collect_inventory(self, host_id: str, host_raw: Dict[str, Any]) -> HostInventory:
        """
        Wyciąga dane inwentaryzacyjne z obiektu hosta Zabbix (selectInventory: 'extend').
        """
        raw_inv = host_raw.get("inventory") or {}
        if isinstance(raw_inv, list):
            raw_inv = raw_inv[0] if raw_inv else {}

        # Wyciąganie adresów IP i MAC z interfejsów
        ips: List[str] = []
        macs: List[str] = []

        for iface in host_raw.get("interfaces", []):
            if iface.get("ip") and iface["ip"] not in ips:
                ips.append(iface["ip"])

        # Inventory MACs
        for k in ["macaddress_a", "macaddress_b"]:
            if raw_inv.get(k):
                macs.append(raw_inv[k])

        return HostInventory(
            os=raw_inv.get("os") or raw_inv.get("os_full") or raw_inv.get("software_app_a"),
            os_full=raw_inv.get("os_full"),
            os_short=raw_inv.get("os_short"),
            hardware=raw_inv.get("hardware") or raw_inv.get("hardware_full"),
            hardware_full=raw_inv.get("hardware_full"),
            serial_number=raw_inv.get("serialno_a") or raw_inv.get("serialno_b"),
            vendor=raw_inv.get("vendor"),
            model=raw_inv.get("model"),
            mac_addresses=macs,
            ip_addresses=ips,
            location=raw_inv.get("location") or raw_inv.get("site_address_a"),
            contact=raw_inv.get("contact"),
            notes=raw_inv.get("notes"),
            raw_inventory=raw_inv,
        )

    def fetch_all_items(self, host_id: str) -> List[Dict[str, Any]]:
        """
        Pobiera wszystkie aktywne i monitorowane Item-y dla danego hosta (item.get).
        """
        logger.debug(f"Pobieranie listy Itemów dla hostid={host_id} (item.get)...")
        params = {
            "hostids": [host_id],
            "output": ["itemid", "name", "key_", "lastvalue", "units", "value_type", "state", "status", "lastclock"],
            "filter": {"status": 0},  # Tylko aktywne (monitored)
            "monitored": True,
        }
        items = self.client.call("item.get", params)
        return items if isinstance(items, list) else []

    def collect_metrics(self, host_id: str, items: Optional[List[Dict[str, Any]]] = None) -> HostMetrics:
        """
        Filtruje kluczowe metryki CPU, RAM, dysków i uptime na podstawie kluczy Zabbix (item.get).
        """
        if items is None:
            items = self.fetch_all_items(host_id)

        metrics = HostMetrics()
        drives_map: Dict[str, Dict[str, Any]] = {}
        raw_sample: Dict[str, Any] = {}

        for it in items:
            key = it.get("key_", "")
            name = it.get("name_", "") or it.get("name", "")
            lastval = it.get("lastvalue")

            if lastval is None or lastval == "":
                continue

            # --- 1. CPU Metrics ---
            if re.search(r"system\.cpu\.util|perf_counter.*processor.*time|perf_counter_en.*processor.*time", key, re.IGNORECASE):
                try:
                    val = float(lastval)
                    if metrics.cpu_utilization_percent is None or "total" in key.lower() or "_total" in key.lower():
                        metrics.cpu_utilization_percent = round(val, 2)
                        raw_sample["cpu_util_item"] = {"key": key, "name": name, "val": lastval}
                except (ValueError, TypeError):
                    pass

            if re.search(r"system\.cpu\.num|wmi\.get.*numberoflogicalprocessors|system\.hw\.cpu\[.*count\]", key, re.IGNORECASE):
                try:
                    metrics.cpu_cores = int(float(lastval))
                    raw_sample["cpu_cores_item"] = {"key": key, "name": name, "val": lastval}
                except (ValueError, TypeError):
                    pass

            # --- 2. Memory (RAM) Metrics ---
            # Total RAM
            if re.search(r"vm\.memory\.size\[total\]|wmi\.get.*totalphysicalmemory|system\.hw\.mac.*memory", key, re.IGNORECASE):
                try:
                    val_bytes = int(float(lastval))
                    metrics.memory_total_bytes = val_bytes
                    metrics.memory_total_formatted = self.format_bytes(val_bytes)
                except (ValueError, TypeError):
                    pass

            # Used RAM
            if re.search(r"vm\.memory\.size\[used\]", key, re.IGNORECASE):
                try:
                    val_bytes = int(float(lastval))
                    metrics.memory_used_bytes = val_bytes
                    metrics.memory_used_formatted = self.format_bytes(val_bytes)
                except (ValueError, TypeError):
                    pass

            # Available / Free RAM
            if re.search(r"vm\.memory\.size\[available\]|vm\.memory\.size\[free\]|perf_counter.*available\s+bytes", key, re.IGNORECASE):
                try:
                    val_bytes = int(float(lastval))
                    metrics.memory_free_bytes = val_bytes
                    metrics.memory_free_formatted = self.format_bytes(val_bytes)
                except (ValueError, TypeError):
                    pass

            # Memory Utilization %
            if re.search(r"vm\.memory\.util|vm\.memory\.size\[pused\]|perf_counter.*% committed bytes in use", key, re.IGNORECASE):
                try:
                    metrics.memory_utilization_percent = round(float(lastval), 2)
                except (ValueError, TypeError):
                    pass

            # --- 3. Uptime ---
            if re.search(r"system\.uptime|perf_counter.*system up time", key, re.IGNORECASE):
                try:
                    uptime_sec = int(float(lastval))
                    metrics.uptime_seconds = uptime_sec
                    metrics.uptime_formatted = self.format_uptime(uptime_sec)
                except (ValueError, TypeError):
                    pass

            # --- 4. Disks / Filesystems ---
            # np. vfs.fs.size[C:,total], vfs.fs.size["C:",used], vfs.fs.size[D:,pused]
            fs_match = re.search(r"vfs\.fs\.size\[\"?([A-Za-z]:|[A-Za-z0-9_\\/\-]+)\"?\s*,\s*([a-zA-Z]+)\]", key)
            if fs_match:
                drive_letter = fs_match.group(1).upper().replace('"', '').strip()
                metric_type = fs_match.group(2).lower()

                if drive_letter not in drives_map:
                    drives_map[drive_letter] = {"fs_name": drive_letter}

                try:
                    num_val = float(lastval)
                    if metric_type == "total":
                        drives_map[drive_letter]["total_bytes"] = int(num_val)
                    elif metric_type == "used":
                        drives_map[drive_letter]["used_bytes"] = int(num_val)
                    elif metric_type in ["free", "avail"]:
                        drives_map[drive_letter]["free_bytes"] = int(num_val)
                    elif metric_type in ["pused", "used_percent"]:
                        drives_map[drive_letter]["used_percent"] = round(num_val, 2)
                    elif metric_type in ["pfree", "free_percent"]:
                        drives_map[drive_letter]["free_percent"] = round(num_val, 2)
                except (ValueError, TypeError):
                    pass

        # Obliczenie brakujących procentów pamięci RAM
        if metrics.memory_utilization_percent is None and metrics.memory_total_bytes:
            if metrics.memory_used_bytes:
                metrics.memory_utilization_percent = round((metrics.memory_used_bytes / metrics.memory_total_bytes) * 100, 2)
            elif metrics.memory_free_bytes:
                used = metrics.memory_total_bytes - metrics.memory_free_bytes
                metrics.memory_used_bytes = used
                metrics.memory_used_formatted = self.format_bytes(used)
                metrics.memory_utilization_percent = round((used / metrics.memory_total_bytes) * 100, 2)

        # Składanie DriveMetric
        for fs_name, d_data in sorted(drives_map.items()):
            tot = d_data.get("total_bytes")
            used = d_data.get("used_bytes")
            free = d_data.get("free_bytes")
            u_pct = d_data.get("used_percent")
            f_pct = d_data.get("free_percent")

            if tot and used and u_pct is None:
                u_pct = round((used / tot) * 100, 2)
            if tot and free and f_pct is None:
                f_pct = round((free / tot) * 100, 2)
            if u_pct is not None and f_pct is None:
                f_pct = round(100.0 - u_pct, 2)
            if f_pct is not None and u_pct is None:
                u_pct = round(100.0 - f_pct, 2)

            metrics.drives.append(
                DriveMetric(
                    fs_name=fs_name,
                    total_bytes=tot,
                    total_formatted=self.format_bytes(tot),
                    used_bytes=used,
                    used_formatted=self.format_bytes(used),
                    free_bytes=free,
                    free_formatted=self.format_bytes(free),
                    used_percent=u_pct,
                    free_percent=f_pct,
                )
            )

        metrics.raw_items_sample = raw_sample
        return metrics

    def collect_services(self, host_id: str, items: Optional[List[Dict[str, Any]]] = None) -> List[WindowsService]:
        """
        Pobiera i analizuje monitorowane usługi Windows (service.info[*], services[*]).
        """
        if items is None:
            items = self.fetch_all_items(host_id)

        services: Dict[str, WindowsService] = {}

        for it in items:
            key = it.get("key_", "")
            name = it.get("name", "")
            lastval = str(it.get("lastvalue", "")).strip()

            # Dopasowanie kluczy typu service.info[service_name, state] lub service.info[service_name, startup]
            svc_match = re.search(r"service\.info\[\"?([^\],]+)\"?\s*(?:,\s*([^\],]+))?\]", key, re.IGNORECASE)
            if svc_match:
                svc_name = svc_match.group(1).strip()
                param_type = (svc_match.group(2) or "state").strip().lower()

                if svc_name not in services:
                    services[svc_name] = WindowsService(
                        name=svc_name,
                        display_name=name if "service" in name.lower() or "usługa" in name.lower() else None,
                        state="Unknown",
                        item_key=key,
                        raw_value=lastval,
                    )

                if param_type == "state":
                    state_str = self.SERVICE_STATES.get(lastval, f"State({lastval})")
                    services[svc_name].state = state_str
                    services[svc_name].raw_value = lastval
                elif param_type == "startup":
                    startup_str = self.SERVICE_STARTUP_TYPES.get(lastval, f"Startup({lastval})")
                    services[svc_name].startup_type = startup_str

            # Inne wykrycia usług (np. z szablonów WMI lub skryptów)
            elif "windows service" in name.lower() or "usługa windows" in name.lower():
                if key not in services:
                    state_str = "Running" if lastval in ["0", "1", "running"] else lastval
                    services[key] = WindowsService(
                        name=name,
                        display_name=name,
                        state=state_str,
                        item_key=key,
                        raw_value=lastval,
                    )

        return sorted(list(services.values()), key=lambda s: (s.state != "Running", s.name))

    def collect_virtualization_data(self, host_id: str, items: Optional[List[Dict[str, Any]]] = None) -> HyperVData:
        """
        Pobiera metryki i listę maszyn wirtualnych jeśli serwer pełni rolę Hyper-V (Hyper-V templates).
        """
        if items is None:
            items = self.fetch_all_items(host_id)

        hyperv_data = HyperVData()
        vms_map: Dict[str, Dict[str, Any]] = {}
        raw_hyperv: Dict[str, Any] = {}

        for it in items:
            key = it.get("key_", "")
            name = it.get("name", "")
            lastval = str(it.get("lastvalue", "")).strip()

            # Sprawdzenie obecności kluczy Hyper-V
            if re.search(r"hyperv|msvm_|hyper-v", key, re.IGNORECASE) or "hyper-v" in name.lower():
                hyperv_data.is_hyperv_host = True
                raw_hyperv[key] = {"name": name, "value": lastval}

                # Wykrywanie maszyn wirtualnych np. wmi.get[..., Select ElementName from Msvm_ComputerSystem]
                # lub perf_counter["\Hyper-V Virtual Machine Health Summary\Total Health Issues"]
                # lub perf_counter["\Hyper-V Hypervisor Virtual Processor(VM_NAME:HV VP 0)\% Guest Run Time"]
                vm_name_match = re.search(r"Hyper-V.*?VM\(([^)]+)\)|Hyper-V.*?Processor\(([^:]+):|vm\.state\[\"?([^\"]+)\"?\]", key, re.IGNORECASE)
                if vm_name_match:
                    vm_name = next(g for g in vm_name_match.groups() if g is not None).strip()
                    if vm_name not in ["_Total", "Total", "root", ""]:
                        if vm_name not in vms_map:
                            vms_map[vm_name] = {
                                "vm_name": vm_name,
                                "state": "Running" if "run time" in key.lower() or "processor" in key.lower() else "Unknown",
                                "raw_attributes": {},
                            }
                        vms_map[vm_name]["raw_attributes"][key] = lastval

                # Stan maszyn wirtualnych z itemów
                if "virtual machines" in name.lower() or "active virtual machines" in name.lower():
                    try:
                        hyperv_data.virtual_machines_count = max(hyperv_data.virtual_machines_count, int(float(lastval)))
                    except (ValueError, TypeError):
                        pass

        # Jeśli wykryto gości Hyper-V
        if vms_map:
            hyperv_data.is_hyperv_host = True
            for vm_name, vm_dict in sorted(vms_map.items()):
                hyperv_data.guest_vms.append(
                    HyperVGuestVM(
                        vm_name=vm_dict["vm_name"],
                        state=vm_dict.get("state", "Unknown"),
                        raw_attributes=vm_dict.get("raw_attributes", {}),
                    )
                )
            hyperv_data.virtual_machines_count = max(hyperv_data.virtual_machines_count, len(hyperv_data.guest_vms))

        hyperv_data.raw_hyperv_metrics = raw_hyperv
        return hyperv_data

    def execute_remote_probe(
        self,
        host_id: str,
        script_name_or_cmd: Optional[str] = None,
    ) -> Optional[RemoteExecutionResult]:
        """
        Wykonuje zdalne polecenie/skrypt na hoście przez Zabbix API (script.execute).
        Przechwytuje wartość 'value' zwróconą z agenta.
        """
        logger.info(f"Wykonywanie zdalnej sondy na hostid={host_id} (script.execute)...")
        
        try:
            # 1. Pobranie dostępnych skryptów w Zabbixie dla danego hosta (script.get)
            available_scripts = self.client.call("script.get", {"hostids": [host_id]})
            target_script = None

            if script_name_or_cmd:
                # Szukamy po nazwie lub ID
                for sc in available_scripts:
                    if sc.get("name", "").lower() == script_name_or_cmd.lower() or sc.get("scriptid") == script_name_or_cmd:
                        target_script = sc
                        break

            if not target_script and available_scripts:
                # Wybieramy pierwszy pasujący skrypt sieciowy / diagnostyczny lub pierwszy z listy
                for sc in available_scripts:
                    sc_name = sc.get("name", "").lower()
                    if any(term in sc_name for term in ["port", "probe", "powershell", "netstat", "tcp", "sniffer", "diag"]):
                        target_script = sc
                        break
                if not target_script:
                    target_script = available_scripts[0]

            if not target_script:
                logger.warning(f"Brak zdefiniowanych lub dopasowanych skryptów w Zabbixie dla hostid={host_id}.")
                return None

            script_id = target_script["scriptid"]
            script_name = target_script.get("name", f"Script_{script_id}")
            logger.info(f"Uruchamianie skryptu Zabbix '{script_name}' (ID: {script_id})...")

            # 2. Wywołanie script.execute
            exec_params = {
                "scriptid": script_id,
                "hostid": host_id,
            }
            exec_res = self.client.call("script.execute", exec_params)
            
            raw_output = ""
            if isinstance(exec_res, dict):
                raw_output = exec_res.get("value", "")
            elif isinstance(exec_res, str):
                raw_output = exec_res

            # 3. Parsowanie portów nasłuchujących jeśli skrypt zwrócił tabelę/PowerShell Get-NetTCPConnection
            parsed_ports = self._parse_listening_ports(raw_output)

            return RemoteExecutionResult(
                script_name=script_name,
                command=target_script.get("command"),
                success=True,
                raw_output=raw_output,
                parsed_listening_ports=parsed_ports,
            )

        except ZabbixAPIException as exc:
            logger.error(f"Błąd wykonania zdalnego skryptu na hostid={host_id}: {exc}")
            return RemoteExecutionResult(
                script_name=script_name_or_cmd or "Unknown",
                success=False,
                error_message=str(exc),
            )

    @staticmethod
    def _parse_listening_ports(output: str) -> List[Dict[str, Any]]:
        """
        Pomocnik parsowania wyjścia z PowerShell (np. Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess).
        """
        ports: List[Dict[str, Any]] = []
        lines = output.strip().splitlines()
        for line in lines:
            line_str = line.strip()
            # Przykłady: "0.0.0.0:443" lub "TCP 0.0.0.0:1433" lub "LocalPort: 80"
            match_ip_port = re.search(r"(?:TCP|UDP)?\s*([0-9\.\*]+|\[::\]|::):(\d+)", line_str, re.IGNORECASE)
            if match_ip_port:
                ip = match_ip_port.group(1)
                port = int(match_ip_port.group(2))
                ports.append({"address": ip, "port": port, "raw_entry": line_str})
        return ports

    def _synthesize_llm_hints(
        self,
        inventory: HostInventory,
        metrics: HostMetrics,
        services: List[WindowsService],
        hyperv: HyperVData,
        remote_res: Optional[RemoteExecutionResult],
    ) -> Dict[str, Any]:
        """
        Syntetyzuje podpowiedzi kontekstowe i wykryte sygnatury aplikacji dla modelu LLM.
        """
        detected_roles: List[str] = []
        active_service_names = [s.name.lower() for s in services if s.state == "Running"]

        # Sygnatury ról Windows
        if any("ntds" in s or "adws" in s or "kdc" in s or "dns" in s for s in active_service_names):
            detected_roles.append("Active Directory Domain Controller / DNS")
        if any("mssql" in s or "sqlserver" in s or "sqlbrowser" in s for s in active_service_names):
            detected_roles.append("Microsoft SQL Server Database Engine")
        if any("w3svc" in s or "was" in s or "iisadmin" in s for s in active_service_names):
            detected_roles.append("Microsoft IIS Web Application Server")
        if any("vmms" in s or "nvspwmi" in s for s in active_service_names) or hyperv.is_hyperv_host:
            detected_roles.append("Microsoft Hyper-V Virtualization Host")
        if any("spooler" in s for s in active_service_names):
            detected_roles.append("Print Server")
        if any("veeam" in s for s in active_service_names):
            detected_roles.append("Veeam Backup & Replication Component")
        if any("exchange" in s or "msexchange" in s for s in active_service_names):
            detected_roles.append("Microsoft Exchange Mail Server")

        hints = {
            "detected_signatures": detected_roles,
            "running_services_count": len([s for s in services if s.state == "Running"]),
            "stopped_services_count": len([s for s in services if s.state != "Running"]),
            "total_storage_drives": len(metrics.drives),
            "is_hyperv_enabled": hyperv.is_hyperv_host,
            "hyperv_guest_count": len(hyperv.guest_vms),
            "remote_probe_executed": remote_res is not None and remote_res.success,
        }
        return hints

    def analyze_host(self, host_identifier: str, run_remote_probe: bool = False, script_name: Optional[str] = None) -> HostAnalysisPayload:
        """
        Główna metoda analityczna - orkiestruje pobranie inwentarza, telemetrii, usług i buduje payload.
        """
        logger.info(f"Rozpoczynanie analizy hosta '{host_identifier}'...")
        
        # 1. Pobranie metadanych hosta
        host_raw = self.fetch_host_details(host_identifier)
        host_id = host_raw["hostid"]
        host_name = host_raw.get("host", host_identifier)
        visible_name = host_raw.get("name", host_name)
        status_str = "Monitored" if str(host_raw.get("status")) == "0" else "Unmonitored"

        host_groups = [g["name"] for g in host_raw.get("groups", []) if "name" in g]
        tags = [HostTag(tag=t["tag"], value=t.get("value", "")) for t in host_raw.get("tags", [])]
        interfaces = [
            HostInterface(
                interfaceid=i["interfaceid"],
                ip=i.get("ip", ""),
                dns=i.get("dns", ""),
                port=i.get("port", "10050"),
                type=int(i.get("type", 1)),
                main=int(i.get("main", 1)),
            )
            for i in host_raw.get("interfaces", [])
        ]

        # 2. Pobranie wszystkich Itemów dla hosta
        items = self.fetch_all_items(host_id)
        logger.info(f"Pobrano {len(items)} monitorowanych itemów dla hosta {host_name} (hostid={host_id}).")

        # 3. Zbieranie poszczególnych domen danych
        inventory = self.collect_inventory(host_id, host_raw)
        metrics = self.collect_metrics(host_id, items)
        services = self.collect_services(host_id, items)
        hyperv = self.collect_virtualization_data(host_id, items)

        # 4. Opcjonalne zdalne wykonanie skryptu (Remote Execution)
        remote_res: Optional[RemoteExecutionResult] = None
        if run_remote_probe:
            remote_res = self.execute_remote_probe(host_id, script_name_or_cmd=script_name)

        # 5. Budowa syntetycznych podpowiedzi dla LLM
        llm_hints = self._synthesize_llm_hints(inventory, metrics, services, hyperv, remote_res)

        payload = HostAnalysisPayload(
            host_id=host_id,
            host_name=host_name,
            visible_name=visible_name,
            status=status_str,
            host_groups=host_groups,
            tags=tags,
            interfaces=interfaces,
            inventory=inventory,
            metrics=metrics,
            windows_services=services,
            hyperv=hyperv,
            remote_execution=remote_res,
            llm_context_hints=llm_hints,
        )

        logger.info(f"Zakończono analizę hosta {host_name}. Wykryto ról: {len(llm_hints.get('detected_signatures', []))}.")
        return payload
