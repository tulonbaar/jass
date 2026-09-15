"""
Unit tests for the JASS built-in probe catalog (jass.core.probes).
"""

import unittest

from jass.core.probes import (
    PROBE_CATALOG,
    get_probe,
    list_probe_keys,
    parse_disk_content_scan,
    parse_event_log_errors,
    parse_hardware_inventory,
    parse_installed_applications,
    parse_listening_ports,
)


class TestProbeCatalog(unittest.TestCase):

    def test_catalog_contains_expected_probes(self):
        keys = list_probe_keys()
        for expected in [
            "listening_ports",
            "hardware_inventory",
            "installed_applications",
            "event_log_errors",
            "disk_content_scan",
        ]:
            self.assertIn(expected, keys)

    def test_get_probe_case_insensitive(self):
        self.assertIsNotNone(get_probe("Hardware_Inventory"))
        self.assertIsNone(get_probe("does_not_exist"))

    def test_every_probe_has_a_zabbix_script_name_and_command(self):
        for probe in PROBE_CATALOG.values():
            self.assertTrue(probe.zabbix_script_name.startswith("JASS - "))
            self.assertIn("powershell.exe", probe.command.lower())


class TestProbeParsers(unittest.TestCase):

    def test_parse_listening_ports_json(self):
        raw = '[{"LocalAddress":"0.0.0.0","LocalPort":443,"OwningProcess":1234}]'
        parsed = parse_listening_ports(raw)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["port"], 443)

    def test_parse_listening_ports_plain_text_fallback(self):
        raw = "TCP    0.0.0.0:3389    0.0.0.0:0    LISTENING"
        parsed = parse_listening_ports(raw)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["port"], 3389)

    def test_parse_hardware_inventory(self):
        raw = '{"SerialNumber":"ABC123","Manufacturer":"HPE","Model":"ProLiant DL380","MacAddresses":["AA:BB:CC:DD:EE:FF"]}'
        parsed = parse_hardware_inventory(raw)
        self.assertEqual(parsed["serial_number"], "ABC123")
        self.assertEqual(parsed["manufacturer"], "HPE")
        self.assertEqual(parsed["mac_addresses"], ["AA:BB:CC:DD:EE:FF"])

    def test_parse_hardware_inventory_ignores_powershell_noise(self):
        raw = 'WARNING: some noisy line\n{"SerialNumber":"XYZ","Manufacturer":"Dell","Model":"R750","MacAddresses":[]}\n'
        parsed = parse_hardware_inventory(raw)
        self.assertEqual(parsed["serial_number"], "XYZ")

    def test_parse_installed_applications(self):
        raw = '[{"DisplayName":"7-Zip","DisplayVersion":"23.01","Publisher":"Igor Pavlov","InstallDate":"20240101"},{"DisplayVersion":"1.0"}]'
        parsed = parse_installed_applications(raw)
        # Entry without DisplayName should be filtered out
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["name"], "7-Zip")
        self.assertEqual(parsed[0]["version"], "23.01")

    def test_parse_event_log_errors(self):
        raw = (
            '[{"TimeCreated":"2024-05-01T00:00:00","LogName":"System","Id":7031,'
            '"LevelDisplayName":"Error","ProviderName":"Service Control Manager","Message":"Boom"}]'
        )
        parsed = parse_event_log_errors(raw)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["event_id"], 7031)
        self.assertEqual(parsed[0]["level"], "Error")

    def test_parse_disk_content_scan_flags_non_standard_folders(self):
        raw = (
            '[{"Drive":"C:\\\\","Folder":"Windows","Standard":true},'
            '{"Drive":"C:\\\\","Folder":"MyCustomApp","Standard":false},'
            '{"Drive":"D:\\\\","Folder":"SQLData","Standard":false}]'
        )
        parsed = parse_disk_content_scan(raw)
        self.assertEqual(len(parsed["all_folders"]), 3)
        non_standard_names = {f["folder"] for f in parsed["non_standard_folders"]}
        self.assertEqual(non_standard_names, {"MyCustomApp", "SQLData"})

    def test_parsers_handle_empty_output_gracefully(self):
        self.assertEqual(parse_listening_ports(""), [])
        self.assertEqual(parse_installed_applications(""), [])
        self.assertEqual(parse_event_log_errors(""), [])
        self.assertEqual(parse_disk_content_scan(""), [])
        self.assertEqual(parse_hardware_inventory(""), {"raw": ""})


if __name__ == "__main__":
    unittest.main()
