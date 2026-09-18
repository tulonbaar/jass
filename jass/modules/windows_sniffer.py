"""
JASS - Just Another System Sniffer
Sniffer module for Microsoft Windows Server and Hyper-V platforms
"""

from __future__ import annotations

import logging
import re
import json
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
    Dedicated telemetry sniffer for Microsoft Windows and Hyper-V hosts.
    Extracts inventory, performance metrics, Windows services, Hyper-V virtual machines,
    and executes remote probes via Zabbix API.
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
        """Formats raw bytes into human-readable unit string (B, KB, MB, GB, TB)."""
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
        """Formats uptime in seconds into human-readable days, hours, minutes."""
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
        Retrieves core host metadata from Zabbix API (`host.get`).
        Supports searching by technical host name, visible name, or numeric hostid.
        """
        logger.debug(f"Retrieving host details for '{host_identifier}' (host.get)...")
        
        params: Dict[str, Any] = {
            "output": ["hostid", "host", "name", "status", "description"],
            "selectInterfaces": ["interfaceid", "ip", "dns", "port", "type", "main"],
            "selectGroups": ["groupid", "name"],
            "selectHostGroups": "extend",
            
            "selectTags": "extend",
            "selectInventory": "extend",
        }

        # If identifier is numeric, query by hostid first
        if host_identifier.isdigit():
            params["hostids"] = [host_identifier]
            hosts = self.client.call("host.get", params)
            if hosts:
                return hosts[0]

        # Query by technical host name
        params_by_host = dict(params)
        params_by_host["filter"] = {"host": [host_identifier]}
        hosts = self.client.call("host.get", params_by_host)
        if hosts:
            return hosts[0]

        # Query by visible name
        params_by_name = dict(params)
        params_by_name["filter"] = {"name": [host_identifier]}
        hosts = self.client.call("host.get", params_by_name)
        if hosts:
            return hosts[0]

        # Fuzzy search
        params_search = dict(params)
        params_search["search"] = {"name": host_identifier, "host": host_identifier}
        params_search["searchByAny"] = True
        hosts = self.client.call("host.get", params_search)
        if hosts:
            return hosts[0]

        raise ZabbixAPIException(f"Host '{host_identifier}' not found in Zabbix.")

    def collect_inventory(self, host_id: str, host_raw: Dict[str, Any]) -> HostInventory:
        """
        Extracts inventory data from Zabbix host object (selectInventory: 'extend').
        """
        raw_inv = host_raw.get("inventory") or {}
        if isinstance(raw_inv, list):
            raw_inv = raw_inv[0] if raw_inv else {}

        # Extract IPs and MACs
        ips: List[str] = []
        macs: List[str] = []

        for iface in host_raw.get("interfaces", []):
            if iface.get("ip") and iface["ip"] not in ips:
                ips.append(iface["ip"])

        # Inventory MAC fields
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
        Retrieves all active, monitored items for the given host (`item.get`).
        """
        logger.debug(f"Retrieving monitored items for hostid={host_id} (item.get)...")
        params = {
            "hostids": [host_id],
            "output": ["itemid", "name", "key_", "lastvalue", "units", "value_type", "state", "status", "lastclock"],
            "filter": {"status": 0},  # Monitored items only
            "monitored": True,
        }
        items = self.client.call("item.get", params)
        return items if isinstance(items, list) else []

    def collect_metrics(self, host_id: str, items: Optional[List[Dict[str, Any]]] = None) -> HostMetrics:
        """
        Filters key CPU, RAM, disk, and uptime metrics based on standard Zabbix keys (`item.get`).
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
            # Modern Zabbix templates (6.0+) use dependent items with keys such as:
            #   vfs.fs.dependent.size[C:,total] / vfs.fs.dependent.size[C:,used] / [...,pused] / [...,free] / [...,pfree]
            # Legacy templates use the classic non-dependent key:
            #   vfs.fs.size[C:,total] / vfs.fs.size["C:",used] / vfs.fs.size[D:,pused]
            fs_match = re.search(
                r'vfs\.fs\.(?:dependent\.)?size\["?([A-Za-z]:|[A-Za-z0-9_\/\-]+)"?\s*,\s*([a-zA-Z]+)\]',
                key,
            )
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
                continue

            # Raw "Get data" master/dependent item returning the full vfs.fs.get() JSON blob, e.g.:
            #   vfs.fs.dependent[C:,data]  or  vfs.fs.get[C:]
            # Payload: {"fsname":"C:","bytes":{"used":..,"free":..,"total":..,"pused":..,"pfree":..},...}
            fs_json_match = re.search(r'vfs\.fs\.(?:dependent\[|get\[)"?([A-Za-z]:|[A-Za-z0-9_\/\-]+)"?[,\]]', key)
            if fs_json_match and str(lastval).strip().startswith(("{", "[")):
                drive_letter = fs_json_match.group(1).upper().replace('"', '').strip()
                try:
                    parsed = json.loads(lastval)
                    # vfs.fs.get (master item without LLD filter) returns a JSON array of all filesystems
                    fs_entries = parsed if isinstance(parsed, list) else [parsed]
                    for entry in fs_entries:
                        if not isinstance(entry, dict):
                            continue
                        entry_name = str(entry.get("fsname", drive_letter)).upper().strip()
                        bytes_info = entry.get("bytes", {})
                        if entry_name not in drives_map:
                            drives_map[entry_name] = {"fs_name": entry_name}
                        if bytes_info.get("total") is not None:
                            drives_map[entry_name].setdefault("total_bytes", int(bytes_info["total"]))
                        if bytes_info.get("used") is not None:
                            drives_map[entry_name].setdefault("used_bytes", int(bytes_info["used"]))
                        if bytes_info.get("free") is not None:
                            drives_map[entry_name].setdefault("free_bytes", int(bytes_info["free"]))
                        if bytes_info.get("pused") is not None:
                            drives_map[entry_name].setdefault("used_percent", round(float(bytes_info["pused"]), 2))
                        if bytes_info.get("pfree") is not None:
                            drives_map[entry_name].setdefault("free_percent", round(float(bytes_info["pfree"]), 2))
                except (ValueError, TypeError, json.JSONDecodeError):
                    pass

        # Calculate memory percentage if missing
        if metrics.memory_utilization_percent is None and metrics.memory_total_bytes:
            if metrics.memory_used_bytes:
                metrics.memory_utilization_percent = round((metrics.memory_used_bytes / metrics.memory_total_bytes) * 100, 2)
            elif metrics.memory_free_bytes:
                used = metrics.memory_total_bytes - metrics.memory_free_bytes
                metrics.memory_used_bytes = used
                metrics.memory_used_formatted = self.format_bytes(used)
                metrics.memory_utilization_percent = round((used / metrics.memory_total_bytes) * 100, 2)

        # Assemble DriveMetrics
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
        Retrieves and analyzes monitored Windows services (service.info[*], services[*]).
        """
        if items is None:
            items = self.fetch_all_items(host_id)

        services: Dict[str, WindowsService] = {}

        for it in items:
            key = it.get("key_", "")
            name = it.get("name", "")
            lastval = str(it.get("lastvalue", "")).strip()

            # Match keys like service.info[service_name, state] or service.info[service_name, startup]
            # NOTE: the capture groups explicitly exclude the quote character ("), otherwise a
            # trailing quote leaks into the service name for quoted keys, e.g. service.info["BFE",state].
            svc_match = re.search(r'service\.info\["?([^\]",]+)"?\s*(?:,\s*"?([^\]",]+)"?)?\]', key, re.IGNORECASE)
            if svc_match:
                svc_name = svc_match.group(1).strip().strip('"')
                param_type = (svc_match.group(2) or "state").strip().strip('"').lower()

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

    # Maps Microsoft.HyperV.PowerShell.VMState integer values (as emitted by the
    # `zbx-hyperv.ps1` custom template's `Get-VM` collector) to readable labels.
    HYPERV_VM_STATES = {
        "1": "Other",
        "2": "Running",
        "3": "Off",
        "4": "Stopping",
        "6": "Saved",
        "9": "Paused",
        "10": "Starting",
        "11": "Reset",
        "32773": "Saving",
        "32776": "Pausing",
        "32779": "Resuming",
    }

    INTEGRATION_SERVICES_STATES = {
        "0": "Up to date",
        "1": "Update required",
        "2": "Unknown",
    }

    def collect_virtualization_data(self, host_id: str, items: Optional[List[Dict[str, Any]]] = None) -> HyperVData:
        """
        Retrieves Hyper-V virtualization metrics and guest VM lists.

        Supports two Hyper-V data sources:
        1. The custom "Hyper-V VMs via PowerShell" template (`hyperv.vm.<metric>["{#VM.NAME}"]`
           dependent items fed by `hyperv.metrics` / `zbx-hyperv.ps1`), which provides rich
           per-VM telemetry (state, uptime, CPU/memory usage, MAC/IP, checkpoints, replication).
        2. Legacy Hyper-V performance-counter based templates (`Hyper-V ... VM(<name>) ...`),
           kept as a best-effort fallback for hosts without the custom template.
        """
        if items is None:
            items = self.fetch_all_items(host_id)

        hyperv_data = HyperVData()
        vms_map: Dict[str, Dict[str, Any]] = {}
        raw_hyperv: Dict[str, Any] = {}

        # Regex for the custom hyperv.vm.<metric>["VMNAME"] key format, e.g.:
        #   hyperv.vm.state["WEB01"], hyperv.vm.cpu.usage["WEB01"], hyperv.vm.checkpoint.oldest["WEB01"]
        hyperv_vm_key_re = re.compile(r'hyperv\.vm\.([a-z.]+)\["?([^"\]]+)"?\]', re.IGNORECASE)

        for it in items:
            key = it.get("key_", "")
            name = it.get("name", "")
            lastval = str(it.get("lastvalue", "")).strip()

            if not (re.search(r"hyperv|msvm_|hyper-v", key, re.IGNORECASE) or "hyper-v" in name.lower()):
                continue

            hyperv_data.is_hyperv_host = True
            raw_hyperv[key] = {"name": name, "value": lastval}

            # 1. Custom "hyperv.vm.<metric>[VM]" key format (user-provided PowerShell template)
            custom_match = hyperv_vm_key_re.search(key)
            if custom_match:
                metric = custom_match.group(1).lower()
                vm_name = custom_match.group(2).strip().strip('"')
                if vm_name:
                    vm_entry = vms_map.setdefault(vm_name, {"vm_name": vm_name, "raw_attributes": {}})
                    vm_entry["raw_attributes"][key] = lastval
                    vm_entry[metric] = lastval
                continue

            # 2. Legacy performance-counter based key format (fallback heuristic)
            vm_name_match = re.search(r'Hyper-V.*?VM\(([^)]+)\)|Hyper-V.*?Processor\(([^:]+):', key, re.IGNORECASE)
            if vm_name_match:
                vm_name = next(g for g in vm_name_match.groups() if g is not None).strip()
                if vm_name not in ["_Total", "Total", "root", ""]:
                    vm_entry = vms_map.setdefault(vm_name, {"vm_name": vm_name, "raw_attributes": {}})
                    vm_entry["raw_attributes"][key] = lastval
                    if "run time" in key.lower() or "processor" in key.lower():
                        vm_entry.setdefault("state", "Running")

            if "virtual machines" in name.lower() or "active virtual machines" in name.lower():
                try:
                    hyperv_data.virtual_machines_count = max(hyperv_data.virtual_machines_count, int(float(lastval)))
                except (ValueError, TypeError):
                    pass

        if vms_map:
            hyperv_data.is_hyperv_host = True
            for vm_name, vm in sorted(vms_map.items()):
                hyperv_data.guest_vms.append(self._build_guest_vm(vm))
            hyperv_data.virtual_machines_count = max(hyperv_data.virtual_machines_count, len(hyperv_data.guest_vms))

        hyperv_data.raw_hyperv_metrics = raw_hyperv
        return hyperv_data

    def _build_guest_vm(self, vm: Dict[str, Any]) -> HyperVGuestVM:
        """Builds a `HyperVGuestVM` model from a raw metric dict keyed by hyperv.vm.<metric> suffixes."""

        def _int(key: str) -> Optional[int]:
            try:
                return int(float(vm[key])) if key in vm and vm[key] not in ("", None) else None
            except (ValueError, TypeError):
                return None

        def _float(key: str) -> Optional[float]:
            try:
                return float(vm[key]) if key in vm and vm[key] not in ("", None) else None
            except (ValueError, TypeError):
                return None

        def _bool(key: str) -> Optional[bool]:
            if key not in vm or vm[key] in ("", None):
                return None
            return str(vm[key]).strip().lower() in ("1", "true", "yes")

        state_raw = vm.get("state")
        state = self.HYPERV_VM_STATES.get(str(state_raw), vm.get("state", "Unknown")) if state_raw is not None else "Unknown"

        mem_bytes = _int("memory")
        mem_demand_bytes = _int("memory.demand")
        uptime_seconds = _int("uptime")
        int_svc_state_raw = vm.get("intsvcstate") or vm.get("int_svc_state")

        return HyperVGuestVM(
            vm_name=vm["vm_name"],
            state=state,
            cpu_cores=_int("cpu.count"),
            cpu_usage_percent=_float("cpu.usage"),
            memory_allocated_bytes=mem_bytes,
            memory_allocated_formatted=self.format_bytes(mem_bytes),
            memory_demand_bytes=mem_demand_bytes,
            memory_demand_formatted=self.format_bytes(mem_demand_bytes),
            uptime=self.format_uptime(uptime_seconds),
            uptime_seconds=uptime_seconds,
            mac_address=vm.get("mac"),
            ip_address=vm.get("ip"),
            is_clustered=_bool("isclustered"),
            checkpoint_count=_int("checkpoint.count"),
            checkpoint_oldest_age_seconds=_int("checkpoint.oldest"),
            integration_services_version=vm.get("intsvcver"),
            integration_services_state=self.INTEGRATION_SERVICES_STATES.get(str(int_svc_state_raw), int_svc_state_raw)
            if int_svc_state_raw is not None
            else None,
            replication_mode=vm.get("replmode"),
            replication_state=vm.get("replstate"),
            replication_health=vm.get("replhealth"),
            raw_attributes=vm.get("raw_attributes", {}),
        )


    def execute_remote_probe(
        self,
        host_id: str,
        script_name_or_cmd: Optional[str] = None,
        probe_key: Optional[str] = None,
        auto_create_script: bool = True,
    ) -> Optional[RemoteExecutionResult]:
        """
        Executes a remote diagnostic script on host agent via ProberClient.
        """
        logger.info(f"Executing remote task on hostid={host_id} (ProberClient)...")

        from jass.db.database import SessionLocal
        from jass.db.models import ProberTask
        from jass.core.prober_client import ProberClient

        db = SessionLocal()
        try:
            target_task = None
            if probe_key:
                target_task = db.query(ProberTask).filter(ProberTask.name == probe_key).first()
            elif script_name_or_cmd:
                target_task = db.query(ProberTask).filter(ProberTask.name == script_name_or_cmd).first()

            if not target_task:
                logger.warning(f"Unknown task/probe_key. DB has no matching ProberTask.")
                return None

            # Find target IP via zabbix
            interfaces = self.client.call("hostinterface.get", {"output": ["ip"], "hostids": host_id})
            target_ip = interfaces[0]["ip"] if interfaces else None
            if not target_ip:
                logger.error(f"Cannot find IP interface for host {host_id}")
                return None

            client = ProberClient(host_id=host_id, host_ip=target_ip)
            if not client.is_alive():
                logger.error(f"Prober is not alive on {target_ip}. Cannot execute task.")
                return RemoteExecutionResult(
                    script_name=target_task.name,
                    probe_key=probe_key,
                    success=False,
                    error_message="Prober is not alive on target host.",
                )

            logger.info(f"Running Prober task '{target_task.name}'...")
            result = client.execute_script(target_task.content)
            
            success = result.get("exit_code") == 0
            raw_output = result.get("stdout", "")
            if not success:
                logger.error(f"Task failed: {result.get('stderr')}")
                return RemoteExecutionResult(
                    script_name=target_task.name,
                    probe_key=probe_key,
                    success=False,
                    raw_output=raw_output,
                    error_message=result.get("stderr"),
                )

            parsed_data: Any = None
            if target_task.parser_id:
                try:
                    local_env = {}
                    exec(target_task.parser.code, {}, local_env)
                    if "parse" in local_env:
                        parsed_data = local_env["parse"](raw_output)
                except Exception as e:
                    logger.error(f"Parser error: {e}")

            parsed_ports: List[Dict[str, Any]] = []
            if probe_key == "listening_ports" and isinstance(parsed_data, list):
                parsed_ports = parsed_data

            return RemoteExecutionResult(
                script_name=target_task.name,
                probe_key=probe_key,
                command=target_task.content,
                success=True,
                raw_output=raw_output,
                parsed_listening_ports=parsed_ports,
                parsed_data=parsed_data,
            )
        except Exception as exc:
            logger.error(f"Remote script execution error on hostid={host_id}: {exc}")
            return RemoteExecutionResult(
                script_name=script_name_or_cmd or probe_key or "Unknown",
                probe_key=probe_key,
                success=False,
                error_message=str(exc),
            )
        finally:
            db.close()

    def _synthesize_llm_hints(
        self,
        inventory: HostInventory,
        metrics: HostMetrics,
        services: List[WindowsService],
        hyperv: HyperVData,
        remote_res: Optional[RemoteExecutionResult],
    ) -> Dict[str, Any]:
        """
        Synthesizes context hints and detected application signatures for LLM analysis.
        """
        detected_roles: List[str] = []
        active_service_names = [s.name.lower() for s in services if s.state == "Running"]

        # Windows role signatures
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
        if any(s in active_service_names for s in ["termservice", "tscpubrpc", "tssdis", "tsgateway", "lserver"]):
            detected_roles.append("Remote Desktop Services (RDS) / Terminal Server")

        hints = {
            "detected_signatures": detected_roles,
            "running_services_count": len([s for s in services if s.state == "Running"]),
            "stopped_services_count": len([s for s in services if s.state != "Running"]),
            "total_storage_drives": len(metrics.drives),
            "is_hyperv_enabled": hyperv.is_hyperv_host,
            "hyperv_guest_count": len(hyperv.guest_vms),
            "remote_probe_executed": remote_res is not None and remote_res.success,
            "remote_probe_key": remote_res.probe_key if remote_res else None,
        }
        return hints

    @staticmethod
    def _merge_probe_into_inventory(inventory: HostInventory, remote_res: Optional[RemoteExecutionResult]) -> None:
        """
        Enriches `HostInventory` with data from the `hardware_inventory` probe when
        Zabbix Host Inventory fields (serial number, MAC addresses) are missing/incomplete.
        """
        if not remote_res or not remote_res.success or remote_res.probe_key != "hardware_inventory":
            return
        data = remote_res.parsed_data or {}
        if not isinstance(data, dict):
            return
        if not inventory.serial_number and data.get("serial_number"):
            inventory.serial_number = data["serial_number"]
        if not inventory.vendor and data.get("manufacturer"):
            inventory.vendor = data["manufacturer"]
        if not inventory.model and data.get("model"):
            inventory.model = data["model"]
        for mac in data.get("mac_addresses", []) or []:
            if mac and mac not in inventory.mac_addresses:
                inventory.mac_addresses.append(mac)
        if data.get("cpus"):
            inventory.cpus = data["cpus"]
        if data.get("ram_gb") is not None:
            inventory.ram_gb = data["ram_gb"]
        if data.get("nics"):
            inventory.nics = data["nics"]
        if data.get("disks"):
            inventory.disks = data["disks"]

    def analyze_host(
        self,
        host_identifier: str,
        run_remote_probe: bool = False,
        script_name: Optional[str] = None,
        probe_key: Optional[str] = None,
    ) -> HostAnalysisPayload:
        """
        Main analytical method - orchestrates inventory, metrics, services, and builds final payload.
        """
        logger.info(f"Starting analysis for host '{host_identifier}'...")
        
        # 1. Fetch host metadata
        host_raw = self.fetch_host_details(host_identifier)
        host_id = host_raw["hostid"]
        host_name = host_raw.get("host", host_identifier)
        visible_name = host_raw.get("name", host_name)
        status_str = "Monitored" if str(host_raw.get("status")) == "0" else "Unmonitored"

        # Compatibility for Zabbix <6.2 ("groups") and >=6.2 ("hostgroups")
        raw_grps = host_raw.get("hostgroups", []) or host_raw.get("groups", [])
        host_groups = [g["name"] for g in raw_grps if "name" in g]
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

        # 2. Fetch monitored items
        items = self.fetch_all_items(host_id)
        logger.info(f"Fetched {len(items)} monitored items for host {host_name} (hostid={host_id}).")

        # 3. Collect domain datasets
        inventory = self.collect_inventory(host_id, host_raw)
        metrics = self.collect_metrics(host_id, items)
        services = self.collect_services(host_id, items)
        hyperv = self.collect_virtualization_data(host_id, items)

        # 4. Optional Remote Probe
        remote_res: Optional[RemoteExecutionResult] = None
        if run_remote_probe:
            remote_res = self.execute_remote_probe(host_id, script_name_or_cmd=script_name, probe_key=probe_key)
            self._merge_probe_into_inventory(inventory, remote_res)

        # 5. Build LLM Context Hints
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

        logger.info(f"Completed analysis for host {host_name}. Detected role signatures: {len(llm_hints.get('detected_signatures', []))}.")
        return payload
