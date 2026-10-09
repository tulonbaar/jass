import unittest
from fastapi.testclient import TestClient
from jass.ui.app import app
from jass.db.database import Base, engine, SessionLocal
from jass.db.models import HostProperty, PropertyCategory, ProberTask, ProberParser, ZabbixScript

class TestFunctional(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=engine)

    def test_status_endpoint(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("connected", response.json())

    def test_settings_endpoints(self):
        response = self.client.get("/api/admin/settings")
        self.assertEqual(response.status_code, 200)
        
        # Update settings
        payload = {
            "name": "test_script",
            "description": "desc",
            "script_type": 5,
            "execute_on": 1,
            "scope": 2,
            "command": "return true;",
            "timeout": "40s",
            "parameters": [{"name": "test", "value": "test"}],
            "map_to_properties": False
        }
        res = self.client.post("/api/zabbix-scripts", json=payload)
        self.assertEqual(res.status_code, 200)
        script_id = res.json()["id"]

        # Read
        res2 = self.client.get("/api/zabbix-scripts")
        self.assertTrue(any(s["id"] == script_id for s in res2.json()))

        # Update
        payload["name"] = "test_script_updated"
        res3 = self.client.put(f"/api/zabbix-scripts/{script_id}", json=payload)
        self.assertEqual(res3.status_code, 200)
        self.assertEqual(res3.json()["name"], "test_script_updated")

        # Delete
        res4 = self.client.delete(f"/api/zabbix-scripts/{script_id}")
        self.assertEqual(res4.status_code, 200)

if __name__ == '__main__':
    unittest.main()
