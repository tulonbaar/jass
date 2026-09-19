"""
Unit tests for the JASS built-in probe catalog and parsers (jass.db.seeds).
"""

import unittest
from jass.db.seeds import PROBES, PARSERS


def run_parser(parser_key: str, output: str):
    env = {}
    exec(PARSERS[parser_key], env)
    return env["parse"](output)


class TestProbeCatalog(unittest.TestCase):

    def test_catalog_contains_expected_probes(self):
        probe_names = [p["name"] for p in PROBES]
        for expected in [
            "listening_ports",
            "hardware_inventory",
            "installed_applications",
            "event_log_errors",
            "disk_content_scan",
            "rds_info",
            "recent_logins",
        ]:
            self.assertIn(expected, probe_names)

    def test_every_probe_has_description_and_command(self):
        for probe in PROBES:
            self.assertTrue(len(probe["description"]) > 0)
            self.assertTrue(len(probe["command"]) > 0)


class TestProbeParsers(unittest.TestCase):

    def test_parse_listening_ports_json(self):
        raw = '[{"LocalAddress":"0.0.0.0","LocalPort":443,"OwningProcess":1234,"Process":"nginx"}]'
        parsed = run_parser("listening_ports", raw)
        ports = parsed["listening_ports"]
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["port"], 443)
        self.assertEqual(ports[0]["process"], "nginx")

    def test_parse_hardware_inventory(self):
        raw = '{"SerialNumber":"ABC123","Manufacturer":"HPE","Model":"ProLiant DL380","MacAddresses":["AA:BB:CC:DD:EE:FF"],"CPUs":["Intel Xeon"],"RAM_GB":32.5,"NICs":[{"Name":"NIC1","MACAddress":"AA"}],"Disks":[{"Model":"Disk1","Size":123}]}'
        parsed = run_parser("hardware_inventory", raw)
        self.assertEqual(parsed["serial_number"], "ABC123")
        self.assertEqual(parsed["manufacturer"], "HPE")
        self.assertEqual(parsed["mac_addresses"], ["AA:BB:CC:DD:EE:FF"])
        self.assertEqual(parsed["cpus"], ["Intel Xeon"])
        self.assertEqual(parsed["ram_gb"], 32.5)
        self.assertEqual(len(parsed["nics"]), 1)
        self.assertEqual(len(parsed["disks"]), 1)

    def test_parse_installed_applications(self):
        raw = '[{"DisplayName":"7-Zip","DisplayVersion":"23.01","Publisher":"Igor Pavlov","InstallDate":"20240101"},{"DisplayVersion":"1.0"}]'
        parsed = run_parser("installed_applications", raw)
        apps = parsed["installed_applications"]
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["name"], "7-Zip")
        self.assertEqual(apps[0]["version"], "23.01")

    def test_parse_event_log_errors(self):
        raw = (
            '[{"TimeCreated":"2024-05-01T00:00:00","LogName":"System","Id":7031,'
            '"LevelDisplayName":"Error","ProviderName":"Service Control Manager","Message":"Boom"}]'
        )
        parsed = run_parser("event_log_errors", raw)
        events = parsed["event_log_errors"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], 7031)
        self.assertEqual(events[0]["level"], "Error")

    def test_parse_disk_content_scan_flags_non_standard_folders(self):
        raw = (
            '[{"Drive":"C:\\\\","Folder":"Windows","Standard":true},'
            '{"Drive":"C:\\\\","Folder":"MyCustomApp","Standard":false},'
            '{"Drive":"D:\\\\","Folder":"SQLData","Standard":false}]'
        )
        parsed = run_parser("disk_content_scan", raw)
        folders = parsed["disk_content_scan"]
        self.assertEqual(len(folders), 3)
        non_standard_names = {f["folder"] for f in folders if not f.get("is_standard")}
        self.assertEqual(non_standard_names, {"MyCustomApp", "SQLData"})

    def test_parse_recent_logins(self):
        raw = '[{"Name":"Administrator","Count":5},{"Name":"User","Count":1}]'
        parsed = run_parser("recent_logins", raw)
        logins = parsed["recent_logins"]
        self.assertEqual(len(logins), 2)
        self.assertEqual(logins[0]["user"], "Administrator")
        self.assertEqual(logins[0]["count"], 5)

    def test_parse_rds_info(self):
        raw = '{"TSEnabled":true,"Port":3389,"Sessions":"active session"}'
        parsed = run_parser("rds_info", raw)
        rds = parsed["rds_info"]
        self.assertEqual(rds["TSEnabled"], True)
        self.assertEqual(rds["Port"], 3389)

    def test_parsers_handle_empty_output_gracefully(self):
        self.assertEqual(run_parser("listening_ports", ""), {"listening_ports": []})
        self.assertEqual(run_parser("installed_applications", ""), {"installed_applications": []})
        self.assertEqual(run_parser("event_log_errors", ""), {"event_log_errors": []})
        self.assertEqual(run_parser("disk_content_scan", ""), {"disk_content_scan": []})
        self.assertEqual(run_parser("recent_logins", ""), {"recent_logins": []})
        self.assertEqual(run_parser("rds_info", ""), {"rds_info": {}})


if __name__ == "__main__":
    unittest.main()
