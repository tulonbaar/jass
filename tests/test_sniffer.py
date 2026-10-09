"""
Unit tests for WindowsSniffer module and Zabbix telemetry parsing.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from jass.analyzers.zabbix_analyzer import ZabbixAnalyzer
from jass.core.client import ZabbixClient
from jass.core.models import HostAnalysisPayload
from jass.core.prompt_builder import LLMPromptBuilder
from jass.modules.windows_sniffer import WindowsSniffer


class TestWindowsSniffer(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock(spec=ZabbixClient)
        self.sniffer = WindowsSniffer(self.mock_client)

    def test_format_bytes(self):
        self.assertEqual(self.sniffer.format_bytes(1024), "1.00 KB")
        self.assertEqual(self.sniffer.format_bytes(1073741824), "1.00 GB")
        self.assertEqual(self.sniffer.format_bytes(536870912000), "500.00 GB")
        self.assertIsNone(self.sniffer.format_bytes(None))

    def test_format_uptime(self):
        self.assertEqual(self.sniffer.format_uptime(60), "1m 0s")
        self.assertEqual(self.sniffer.format_uptime(3665), "1h 1m 5s")
        self.assertEqual(self.sniffer.format_uptime(90061), "1d 1h 1m 1s")

    def test_collect_inventory(self):
        host_raw = {
            "hostid": "10001",
            "host": "WIN-SRV-SQL01",
            "name": "Production MS SQL DB",
            "interfaces": [{"interfaceid": "1", "ip": "192.168.10.50", "dns": "db01.corp.local"}],
            "inventory": {
                "os": "Windows Server 2022 Datacenter",
                "os_full": "Microsoft Windows Server 2022 Datacenter (10.0.20348)",
                "hardware": "Dell PowerEdge R750",
                "serialno_a": "DELL-SN-998877",
                "vendor": "Dell Inc.",
                "model": "PowerEdge R750",
                "macaddress_a": "00:50:56:AB:CD:EF",
            },
        }

        inv = self.sniffer.collect_inventory("10001", host_raw)
        self.assertEqual(inv.os, "Windows Server 2022 Datacenter")
        self.assertEqual(inv.hardware, "Dell PowerEdge R750")
        self.assertEqual(inv.serial_number, "DELL-SN-998877")
        self.assertIn("192.168.10.50", inv.ip_addresses)
        self.assertIn("00:50:56:AB:CD:EF", inv.mac_addresses)

    def test_collect_metrics(self):
        sample_items = [
            # CPU
            {"itemid": "1", "name": "CPU utilization", "key_": "system.cpu.util", "lastvalue": "18.45"},
            {"itemid": "2", "name": "Number of CPUs", "key_": "system.cpu.num", "lastvalue": "16"},
            # RAM
            {"itemid": "3", "name": "Total memory", "key_": "vm.memory.size[total]", "lastvalue": "68719476736"},  # 64 GB
            {"itemid": "4", "name": "Used memory", "key_": "vm.memory.size[used]", "lastvalue": "34359738368"},   # 32 GB
            # Drives
            {"itemid": "5", "name": "C: Total space", "key_": 'vfs.fs.size["C:",total]', "lastvalue": "214748364800"},  # 200 GB
            {"itemid": "6", "name": "C: Used space", "key_": 'vfs.fs.size["C:",used]', "lastvalue": "107374182400"},   # 100 GB
            {"itemid": "7", "name": "D: Total space", "key_": 'vfs.fs.size[D:,total]', "lastvalue": "1073741824000"},   # 1 TB
            {"itemid": "8", "name": "D: Used space", "key_": 'vfs.fs.size[D:,used]', "lastvalue": "429496729600"},     # 400 GB
            # Uptime
            {"itemid": "9", "name": "System uptime", "key_": "system.uptime", "lastvalue": "864000"},  # 10 days
        ]

        metrics = self.sniffer.collect_metrics("10001", items=sample_items)
        self.assertEqual(metrics.cpu_utilization_percent, 18.45)
        self.assertEqual(metrics.cpu_cores, 16)
        self.assertEqual(metrics.memory_total_formatted, "64.00 GB")
        self.assertEqual(metrics.memory_used_formatted, "32.00 GB")
        self.assertEqual(metrics.memory_utilization_percent, 50.0)
        self.assertEqual(len(metrics.drives), 2)
        
        c_drive = next(d for d in metrics.drives if d.fs_name == "C:")
        self.assertEqual(c_drive.total_formatted, "200.00 GB")
        self.assertEqual(c_drive.used_percent, 50.0)

    def test_collect_metrics_modern_dependent_fs_keys(self):
        # Modern "Windows by Zabbix agent active" template (6.0+) uses dependent items with
        # the "vfs.fs.dependent.size[...]" key format instead of the legacy "vfs.fs.size[...]".
        sample_items = [
            {"itemid": "1", "name": "FS [C:]: Space: Used", "key_": "vfs.fs.dependent.size[C:,used]", "lastvalue": "119036612608"},
            {"itemid": "2", "name": "FS [C:]: Space: Total", "key_": "vfs.fs.dependent.size[C:,total]", "lastvalue": "135810510848"},
            {"itemid": "3", "name": "FS [C:]: Space: Used, in %", "key_": "vfs.fs.dependent.size[C:,pused]", "lastvalue": "87.649043"},
            {"itemid": "4", "name": "FS [C:]: Space: Available", "key_": "vfs.fs.dependent.size[C:,free]", "lastvalue": "16773898240"},
        ]

        metrics = self.sniffer.collect_metrics("10001", items=sample_items)
        self.assertEqual(len(metrics.drives), 1)

        c_drive = metrics.drives[0]
        self.assertEqual(c_drive.fs_name, "C:")
        self.assertEqual(c_drive.total_bytes, 135810510848)
        self.assertEqual(c_drive.used_bytes, 119036612608)
        self.assertEqual(c_drive.free_bytes, 16773898240)
        self.assertEqual(c_drive.used_percent, 87.65)

    def test_collect_metrics_fs_get_data_json_blob(self):
        # The "Get data" master/dependent item returns the raw JSON payload for the filesystem,
        # which JASS should be able to parse directly as a robust fallback.
        raw_json = (
            '{"fsname":"C:","fslabel":"","bytes":{"used":119036612608,"free":16773898240,'
            '"total":135810510848,"pused":87.649043,"pfree":12.350957},'
            '"fsdrivetype":"fixed","fstype":"NTFS"}'
        )
        sample_items = [
            {"itemid": "1", "name": "FS [C:]: Get data", "key_": "vfs.fs.dependent[C:,data]", "lastvalue": raw_json},
        ]

        metrics = self.sniffer.collect_metrics("10001", items=sample_items)
        self.assertEqual(len(metrics.drives), 1)

        c_drive = metrics.drives[0]
        self.assertEqual(c_drive.fs_name, "C:")
        self.assertEqual(c_drive.total_bytes, 135810510848)
        self.assertEqual(c_drive.used_bytes, 119036612608)
        self.assertEqual(c_drive.free_bytes, 16773898240)
        self.assertEqual(c_drive.used_percent, 87.65)
        self.assertEqual(c_drive.free_percent, 12.35)

    def test_collect_services(self):
        sample_items = [
            {"itemid": "1", "name": "MSSQLSERVER Service state", "key_": "service.info[MSSQLSERVER,state]", "lastvalue": "0"},
            {"itemid": "2", "name": "SQLSERVERAGENT Service state", "key_": "service.info[SQLSERVERAGENT,state]", "lastvalue": "0"},
            {"itemid": "3", "name": "W3SVC Service state", "key_": "service.info[W3SVC,state]", "lastvalue": "6"},
            {"itemid": "4", "name": "Spooler Startup Type", "key_": "service.info[Spooler,startup]", "lastvalue": "0"},
        ]

        services = self.sniffer.collect_services("10001", items=sample_items)
        svc_dict = {s.name: s for s in services}
        
        self.assertIn("MSSQLSERVER", svc_dict)
        self.assertEqual(svc_dict["MSSQLSERVER"].state, "Running")
        self.assertIn("W3SVC", svc_dict)
        self.assertEqual(svc_dict["W3SVC"].state, "Stopped")

    def test_collect_services_quoted_keys_no_trailing_quote(self):
        """Regression test: service.info["Name",state] must not leave a trailing quote in the name."""
        sample_items = [
            {"itemid": "1", "name": "AppHostSvc state", "key_": 'service.info["AppHostSvc",state]', "lastvalue": "0"},
            {"itemid": "2", "name": "BFE state", "key_": 'service.info["BFE",state]', "lastvalue": "0"},
            {"itemid": "3", "name": "CryptSvc startup", "key_": 'service.info["CryptSvc",startup]', "lastvalue": "2"},
        ]

        services = self.sniffer.collect_services("10001", items=sample_items)
        names = {s.name for s in services}

        self.assertIn("AppHostSvc", names)
        self.assertIn("BFE", names)
        self.assertIn("CryptSvc", names)
        for n in names:
            self.assertNotIn('"', n)

    def test_collect_hyperv(self):
        sample_items = [
            {"itemid": "1", "name": "Hyper-V VM CRM-PROD Guest Run Time", "key_": r'perf_counter["\Hyper-V Hypervisor Virtual Processor(CRM-PROD:HV VP 0)\% Guest Run Time"]', "lastvalue": "12.5"},
            {"itemid": "2", "name": "Hyper-V VM ERP-DB Guest Run Time", "key_": r'perf_counter["\Hyper-V Hypervisor Virtual Processor(ERP-DB:HV VP 0)\% Guest Run Time"]', "lastvalue": "35.2"},
            {"itemid": "3", "name": "Active virtual machines", "key_": "hyperv.active_vms", "lastvalue": "2"},
        ]

        hv_data = self.sniffer.collect_virtualization_data("10001", items=sample_items)
        self.assertTrue(hv_data.is_hyperv_host)
        self.assertEqual(hv_data.virtual_machines_count, 2)
        vm_names = [v.vm_name for v in hv_data.guest_vms]
        self.assertIn("CRM-PROD", vm_names)
        self.assertIn("ERP-DB", vm_names)

    def test_collect_hyperv_custom_powershell_template(self):
        """Parses the custom 'Hyper-V VMs via PowerShell' (zbx-hyperv.ps1) dependent item keys."""
        sample_items = [
            {"itemid": "1", "name": "VM WEB01 State", "key_": 'hyperv.vm.state["WEB01"]', "lastvalue": "2"},
            {"itemid": "2", "name": "VM WEB01 Uptime", "key_": 'hyperv.vm.uptime["WEB01"]', "lastvalue": "360000"},
            {"itemid": "3", "name": "VM WEB01 CPU Usage", "key_": 'hyperv.vm.cpu.usage["WEB01"]', "lastvalue": "7.5"},
            {"itemid": "4", "name": "VM WEB01 CPU Count", "key_": 'hyperv.vm.cpu.count["WEB01"]', "lastvalue": "4"},
            {"itemid": "5", "name": "VM WEB01 Memory", "key_": 'hyperv.vm.memory["WEB01"]', "lastvalue": "4294967296"},
            {"itemid": "6", "name": "VM WEB01 Memory Demand", "key_": 'hyperv.vm.memory.demand["WEB01"]', "lastvalue": "2147483648"},
            {"itemid": "7", "name": "VM WEB01 MAC", "key_": 'hyperv.vm.mac["WEB01"]', "lastvalue": "00:15:5D:01:02:03"},
            {"itemid": "8", "name": "VM WEB01 IP", "key_": 'hyperv.vm.ip["WEB01"]', "lastvalue": "10.0.0.55"},
            {"itemid": "9", "name": "VM WEB01 Checkpoint Count", "key_": 'hyperv.vm.checkpoint.count["WEB01"]', "lastvalue": "1"},
            {"itemid": "10", "name": "VM WEB01 Checkpoint Oldest", "key_": 'hyperv.vm.checkpoint.oldest["WEB01"]', "lastvalue": "86400"},
            {"itemid": "11", "name": "VM DB02 State", "key_": 'hyperv.vm.state["DB02"]', "lastvalue": "3"},
        ]

        hv_data = self.sniffer.collect_virtualization_data("10001", items=sample_items)
        self.assertTrue(hv_data.is_hyperv_host)
        vm_map = {v.vm_name: v for v in hv_data.guest_vms}

        self.assertIn("WEB01", vm_map)
        web01 = vm_map["WEB01"]
        self.assertEqual(web01.state, "Running")
        self.assertEqual(web01.cpu_cores, 4)
        self.assertAlmostEqual(web01.cpu_usage_percent, 7.5)
        self.assertEqual(web01.memory_allocated_bytes, 4294967296)
        self.assertEqual(web01.memory_allocated_formatted, "4.00 GB")
        self.assertEqual(web01.memory_demand_bytes, 2147483648)
        self.assertEqual(web01.mac_address, "00:15:5D:01:02:03")
        self.assertEqual(web01.ip_address, "10.0.0.55")
        self.assertEqual(web01.checkpoint_count, 1)
        self.assertEqual(web01.checkpoint_oldest_age_seconds, 86400)
        self.assertEqual(web01.uptime_seconds, 360000)

        self.assertIn("DB02", vm_map)
        self.assertEqual(vm_map["DB02"].state, "Off")

    @patch("jass.core.prober_client.ProberClient")
    def test_execute_remote_probe_via_prober(self, mock_prober_cls):
        """When executing remote probe, ProberClient should be invoked with target task content."""
        mock_instance = MagicMock()
        mock_instance.is_alive.return_value = True
        mock_instance.execute_script.return_value = {
            "exit_code": 0,
            "stdout": '{"SerialNumber":"SN-12345","Manufacturer":"Dell Inc.","Model":"PowerEdge R750","MacAddresses":["00:11:22:33:44:55"]}',
            "stderr": ""
        }
        mock_prober_cls.return_value = mock_instance

        def call_side_effect(method, params=None, auth_required=True):
            if method == "hostinterface.get":
                return [{"ip": "10.0.0.1"}]
            return []

        self.mock_client.call.side_effect = call_side_effect

        result = self.sniffer.execute_remote_probe("10001", probe_key="hardware_inventory")

        self.assertIsNotNone(result)
        self.assertTrue(result.success)
        self.assertEqual(result.probe_key, "hardware_inventory")
        self.assertEqual(result.parsed_data["serial_number"], "SN-12345")
        self.assertEqual(result.parsed_data["mac_addresses"], ["00:11:22:33:44:55"])

    @patch("jass.core.prober_client.ProberClient")
    def test_execute_remote_probe_listening_ports(self, mock_prober_cls):
        """When listening_ports probe executes, parsed ports should be populated."""
        mock_instance = MagicMock()
        mock_instance.is_alive.return_value = True
        mock_instance.execute_script.return_value = {
            "exit_code": 0,
            "stdout": '[{"LocalAddress":"0.0.0.0","LocalPort":80,"OwningProcess":4,"Process":"System"}]',
            "stderr": ""
        }
        mock_prober_cls.return_value = mock_instance

        def call_side_effect(method, params=None, auth_required=True):
            if method == "hostinterface.get":
                return [{"ip": "10.0.0.1"}]
            return []

        self.mock_client.call.side_effect = call_side_effect

        result = self.sniffer.execute_remote_probe("10001", probe_key="listening_ports")

        self.assertIsNotNone(result)
        self.assertTrue(result.success)
        self.assertEqual(len(result.parsed_listening_ports), 1)
        self.assertEqual(result.parsed_listening_ports[0]["port"], 80)

    def test_full_analysis_and_llm_prompt_generation(self):
        host_raw = {
            "hostid": "10001",
            "host": "WIN-SRV-AD01",
            "name": "Primary Domain Controller",
            "status": "0",
            "groups": [{"groupid": "1", "name": "Windows Servers"}, {"groupid": "2", "name": "Domain Controllers"}],
            "tags": [{"tag": "Env", "value": "Production"}, {"tag": "Role", "value": "ActiveDirectory"}],
            "interfaces": [{"interfaceid": "1", "ip": "10.0.0.10", "dns": "dc01.corp.local", "port": "10050", "type": 1, "main": 1}],
            "inventory": {
                "os": "Windows Server 2022",
                "os_full": "Windows Server 2022 Standard",
                "hardware": "VMware Virtual Platform",
            },
        }

        sample_items = [
            {"itemid": "1", "name": "CPU", "key_": "system.cpu.util", "lastvalue": "5.2"},
            {"itemid": "2", "name": "RAM Total", "key_": "vm.memory.size[total]", "lastvalue": "17179869184"},  # 16 GB
            {"itemid": "3", "name": "NTDS Active Directory Service", "key_": "service.info[NTDS,state]", "lastvalue": "0"},
            {"itemid": "4", "name": "DNS Server Service", "key_": "service.info[DNS,state]", "lastvalue": "0"},
            {"itemid": "5", "name": "C: Drive Total", "key_": "vfs.fs.size[C:,total]", "lastvalue": "107374182400"},
            {"itemid": "6", "name": "C: Drive Used", "key_": "vfs.fs.size[C:,used]", "lastvalue": "32212254720"},
        ]

        self.mock_client.call.side_effect = lambda method, params=None, auth_required=True: (
            [host_raw] if method == "host.get" else (
                sample_items if method == "item.get" else []
            )
        )

        payload = self.sniffer.analyze_host("WIN-SRV-AD01")
        self.assertIsInstance(payload, HostAnalysisPayload)
        self.assertEqual(payload.host_name, "WIN-SRV-AD01")
        self.assertIn("Active Directory Domain Controller / DNS", payload.llm_context_hints.get("detected_signatures", []))

        # Test JSON serialization and prompt creation
        json_output = payload.to_llm_json()
        parsed_json = json.loads(json_output)
        self.assertEqual(parsed_json["host_name"], "WIN-SRV-AD01")

        prompt = LLMPromptBuilder.build_user_prompt(payload)
        self.assertIn("WIN-SRV-AD01", prompt)
        self.assertIn("NTDS", prompt)


if __name__ == "__main__":
    unittest.main()
