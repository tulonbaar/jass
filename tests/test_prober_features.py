import unittest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from jass.db.database import Base
from jass.db.models import PropertyCategory, HostProperty, HostPropertyValue
from jass.core.prober_client import ProberClient, encrypt_payload, decrypt_payload
from jass.ui.routers.prober import log_host_event, _HOST_LOGS
from jass.ui.routers.admin import (
    create_category, update_category, CategoryCreate,
    create_property, update_property, PropertyCreate
)
from jass.ui.routers.host_properties import get_host_properties

# Create in-memory SQLite DB for testing
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


class TestProberFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=TEST_ENGINE)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=TEST_ENGINE)

    def setUp(self):
        Base.metadata.drop_all(bind=TEST_ENGINE)
        Base.metadata.create_all(bind=TEST_ENGINE)

    def test_prober_client_fetch_logs_and_terminate(self):
        client = ProberClient(host_id="1001", host_ip="127.0.0.1")

        # Test fetch_logs success
        with patch("requests.post") as mock_post:
            encrypted_resp = encrypt_payload({"logs": ["line 1", "line 2"]}, client.config.psk)
            mock_post.return_value = MagicMock(status_code=200, content=encrypted_resp, raise_for_status=lambda: None)
            logs = client.fetch_logs(tail=50)
            self.assertEqual(logs, ["line 1", "line 2"])

        # Test terminate success
        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            result = client.terminate()
            self.assertTrue(result)

        client.close()

    def test_log_host_event_and_isolation(self):
        log_host_event("host_A", "Event A1")
        log_host_event("host_A", "Event A2")
        log_host_event("host_B", "Event B1")

        self.assertIn("Event A1", _HOST_LOGS["host_A"][-2])
        self.assertIn("Event A2", _HOST_LOGS["host_A"][-1])
        self.assertIn("Event B1", _HOST_LOGS["host_B"][-1])
        # Host B must not have Host A's events
        for line in _HOST_LOGS["host_B"]:
            self.assertNotIn("Event A", line)

    def test_admin_category_with_icon(self):
        db = TestingSessionLocal()
        try:
            # Create category with custom icon
            cat_in = CategoryCreate(
                name="virt",
                display_name="Virtualization",
                order=15,
                icon="fa-server"
            )
            cat_obj = create_category(cat=cat_in, db=db)
            self.assertEqual(cat_obj.name, "virt")
            self.assertEqual(cat_obj.icon, "fa-server")

            # Update category icon
            update_in = CategoryCreate(
                name="virt",
                display_name="Virtualization Hyper-V",
                order=16,
                icon="fa-cloud"
            )
            updated = update_category(id=cat_obj.id, cat=update_in, db=db)
            self.assertEqual(updated.icon, "fa-cloud")
            self.assertEqual(updated.display_name, "Virtualization Hyper-V")
        finally:
            db.close()

    def test_admin_property_with_display_mode(self):
        db = TestingSessionLocal()
        try:
            cat = PropertyCategory(name="net", display_name="Network", order=10, icon="fa-network-wired")
            db.add(cat)
            db.commit()

            # Create property with display_mode
            prop_in = PropertyCreate(
                name="ports",
                display_name="Listening Ports",
                description="Active listening sockets",
                data_type="json",
                display_mode="table",
                category_id=cat.id
            )
            prop_obj = create_property(prop=prop_in, db=db)
            self.assertEqual(prop_obj.display_mode, "table")

            # Update property display_mode
            prop_update = PropertyCreate(
                name="ports",
                display_name="Listening Ports",
                description="Active listening sockets",
                data_type="json",
                display_mode="key_value",
                category_id=cat.id
            )
            updated_prop = update_property(id=prop_obj.id, prop=prop_update, db=db)
            self.assertEqual(updated_prop.display_mode, "key_value")
        finally:
            db.close()

    def test_get_host_properties_serialization(self):
        db = TestingSessionLocal()
        try:
            cat = PropertyCategory(name="storage", display_name="Storage Systems", order=1, icon="fa-hard-drive")
            db.add(cat)
            db.flush()
            prop = HostProperty(name="disks", display_name="Physical Disks", data_type="json", display_mode="table", category_id=cat.id)
            db.add(prop)
            db.flush()
            val = HostPropertyValue(host_id="10099", property_id=prop.id, value=[{"drive": "C:", "size_gb": 100}])
            db.add(val)
            db.commit()

            res = get_host_properties(host_id="10099", db=db)
            self.assertEqual(len(res["categories"]), 1)
            c = res["categories"][0]
            self.assertEqual(c["icon"], "fa-hard-drive")
            self.assertEqual(len(c["properties"]), 1)
            p = c["properties"][0]
            self.assertEqual(p["name"], "disks")
            self.assertEqual(p["display_mode"], "table")
            self.assertEqual(p["value"], [{"drive": "C:", "size_gb": 100}])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
