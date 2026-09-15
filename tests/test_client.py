"""
Unit tests for ZabbixClient (JSON-RPC).
"""

import unittest
from unittest.mock import MagicMock, patch
import requests

from jass.core.client import ZabbixAPIException, ZabbixAuthException, ZabbixClient


class TestZabbixClient(unittest.TestCase):

    def test_normalize_api_url(self):
        self.assertEqual(
            ZabbixClient._normalize_api_url("http://zabbix.local"),
            "http://zabbix.local/api_jsonrpc.php",
        )
        self.assertEqual(
            ZabbixClient._normalize_api_url("https://zabbix.local/zabbix/"),
            "https://zabbix.local/zabbix/api_jsonrpc.php",
        )
        self.assertEqual(
            ZabbixClient._normalize_api_url("zabbix.local/api_jsonrpc.php"),
            "http://zabbix.local/api_jsonrpc.php",
        )

    @patch.object(requests.Session, "post")
    def test_connect_with_api_token(self, mock_post):
        # Mock apiinfo.version and test user.get
        mock_version_resp = MagicMock()
        mock_version_resp.json.return_value = {"jsonrpc": "2.0", "result": "6.4.12", "id": 1}
        mock_version_resp.raise_for_status.return_value = None

        mock_user_resp = MagicMock()
        mock_user_resp.json.return_value = {"jsonrpc": "2.0", "result": [{"userid": "1"}], "id": 2}
        mock_user_resp.raise_for_status.return_value = None

        mock_post.side_effect = [mock_version_resp, mock_user_resp]

        client = ZabbixClient(url="http://zabbix.local", api_token="secret_token_123")
        version = client.connect()

        self.assertEqual(version, "6.4.12")
        self.assertTrue(client.is_authenticated)
        self.assertEqual(client.auth_token, "secret_token_123")

    @patch.object(requests.Session, "post")
    def test_connect_with_user_login_fallback(self, mock_post):
        # 1. apiinfo.version
        mock_version_resp = MagicMock()
        mock_version_resp.json.return_value = {"jsonrpc": "2.0", "result": "6.0.0", "id": 1}
        mock_version_resp.raise_for_status.return_value = None

        # 2. user.login
        mock_login_resp = MagicMock()
        mock_login_resp.json.return_value = {"jsonrpc": "2.0", "result": "session_auth_token_xyz", "id": 2}
        mock_login_resp.raise_for_status.return_value = None

        mock_post.side_effect = [mock_version_resp, mock_login_resp]

        client = ZabbixClient(url="http://zabbix.local", username="Admin", password="sample_password")
        version = client.connect()

        self.assertEqual(version, "6.0.0")
        self.assertEqual(client.auth_token, "session_auth_token_xyz")

    @patch.object(requests.Session, "post")
    def test_api_error_handling(self, mock_post):
        mock_err_resp = MagicMock()
        mock_err_resp.json.return_value = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32602,
                "message": "Invalid params.",
                "data": "Host not found",
            },
            "id": 1,
        }
        mock_err_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_err_resp

        client = ZabbixClient(url="http://zabbix.local", api_token="token")
        with self.assertRaises(ZabbixAPIException) as ctx:
            client.call("host.get", {"hostids": ["99999"]})

        self.assertIn("Invalid params.", str(ctx.exception))
        self.assertEqual(ctx.exception.code, -32602)


if __name__ == "__main__":
    unittest.main()
