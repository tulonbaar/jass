"""
JASS - Just Another System Sniffer
Zabbix JSON-RPC API Client
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union
import urllib.parse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("jass.core.client")


class ZabbixAPIException(Exception):
    """Base exception for errors related to Zabbix API queries."""

    def __init__(self, message: str, code: Optional[int] = None, data: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.data = data

    def __str__(self) -> str:
        err = f"Zabbix API Error: {self.message}"
        if self.code is not None:
            err += f" (Code: {self.code})"
        if self.data:
            err += f" - {self.data}"
        return err


class ZabbixAuthException(ZabbixAPIException):
    """Exception raised upon authentication failure."""
    pass


class ZabbixClient:
    """
    Advanced JSON-RPC client for Zabbix API (compatible with Zabbix 6.0+).

    Features:
    - Authentication via API Token (Bearer Token / auth token)
    - Fallback to traditional user/password authentication (`user.login` method)
    - Automatic request retry logic and timeout handling
    - Support for self-signed SSL certificates
    """

    def __init__(
        self,
        url: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 15,
        verify_ssl: bool = True,
        max_retries: int = 3,
    ) -> None:
        """
        Initialize Zabbix API client.

        :param url: Base URL of the Zabbix instance (e.g. https://zabbix.local or https://zabbix.local/api_jsonrpc.php)
        :param api_token: Zabbix API Token (Zabbix 5.4 / 6.0+)
        :param username: Username (used when API token is not provided)
        :param password: Password (used when API token is not provided)
        :param timeout: Request timeout in seconds
        :param verify_ssl: Verify server SSL certificate
        :param max_retries: Maximum number of retries upon network errors
        """
        self.raw_url = url.strip()
        self.api_url = self._normalize_api_url(self.raw_url)
        self.api_token = api_token.strip() if api_token else None
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.auth_token: Optional[str] = self.api_token
        self._req_id = 0

        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self._api_version: Optional[str] = None
        self._api_major_version: float = 0.0

    @staticmethod
    def _normalize_api_url(url: str) -> str:
        """Normalizes the given URL to full api_jsonrpc.php endpoint."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
        
        if not url.endswith("/api_jsonrpc.php"):
            if url.endswith("/"):
                url += "api_jsonrpc.php"
            else:
                url += "/api_jsonrpc.php"
        return url

    @staticmethod
    def _parse_major_version(version_str: str) -> float:
        """Parses a Zabbix version string (e.g. '6.4.12') into a major.minor float (e.g. 6.4)."""
        try:
            parts = version_str.split(".")
            return float(f"{parts[0]}.{parts[1]}")
        except (IndexError, ValueError):
            return 0.0

    @property
    def is_authenticated(self) -> bool:
        """Returns True if the client holds an active auth token."""
        return bool(self.auth_token)

    def connect(self) -> str:
        """
        Establishes connection to Zabbix API, retrieves server version, and authenticates.

        :return: Zabbix API version string (e.g. '6.4.12')
        :raises ZabbixAuthException: On authentication failure
        :raises ZabbixAPIException: On API communication error
        """
        logger.info(f"Connecting to Zabbix API at: {self.api_url}")
        
        # 1. Check API version (does not require authentication)
        self._api_version = self.get_version()
        self._api_major_version = self._parse_major_version(self._api_version)
        logger.info(f"Detected Zabbix API version: {self._api_version}")

        # 2. Authentication
        if self.api_token:
            logger.info("Using API Token for authentication.")
            self.auth_token = self.api_token
            # Verify token with a lightweight call
            try:
                self.call("user.get", {"output": ["userid", "username"]})
                logger.info("Authentication via API Token successful.")
                return self._api_version
            except ZabbixAPIException as exc:
                logger.warning(f"API Token validation failed ({exc}). Attempting fallback...")
                if not (self.username and self.password):
                    raise ZabbixAuthException(f"Invalid API Token: {exc.message}")

        if self.username and self.password:
            logger.info(f"Performing login for user '{self.username}' (user.login)...")
            self._login(self.username, self.password)
            return self._api_version

        raise ZabbixAuthException("Missing credentials (either API Token or username/password required).")

    def get_version(self) -> str:
        """Calls `apiinfo.version` method to retrieve Zabbix API version."""
        resp = self.call("apiinfo.version", {}, auth_required=False)
        if isinstance(resp, str):
            return resp
        raise ZabbixAPIException(f"Unexpected API version format: {resp}")

    def _login(self, username: str, password: str) -> str:
        """
        Authenticates using `user.login` method.
        Compatible with Zabbix 6.0+ ('username' field) and legacy versions ('user' field).
        """
        params_v6 = {"username": username, "password": password}
        try:
            token = self.call("user.login", params_v6, auth_required=False)
            self.auth_token = str(token)
            logger.info("Logged in successfully using user.login.")
            return self.auth_token
        except ZabbixAPIException as e:
            # Fallback for legacy parameter naming
            try:
                params_legacy = {"user": username, "password": password}
                token = self.call("user.login", params_legacy, auth_required=False)
                self.auth_token = str(token)
                logger.info("Logged in successfully (legacy param: user).")
                return self.auth_token
            except ZabbixAPIException:
                raise ZabbixAuthException(f"Zabbix user.login failed: {e.message}")

    def logout(self) -> bool:
        """Logs out session if authenticated via username/password."""
        if self.auth_token and not self.api_token:
            try:
                self.call("user.logout", {})
                self.auth_token = None
                logger.info("Logged out Zabbix API session.")
                return True
            except Exception as e:
                logger.debug(f"Error during logout: {e}")
        return False

    def call(
        self,
        method: str,
        params: Optional[Union[Dict[str, Any], List[Any]]] = None,
        auth_required: bool = True,
    ) -> Any:
        """
        Executes a JSON-RPC 2.0 request against Zabbix API.

        :param method: Zabbix API method name (e.g. host.get, item.get)
        :param params: Parameters dictionary or list
        :param auth_required: Whether the method requires authentication
        :return: Result from the 'result' field of the JSON-RPC response
        :raises ZabbixAuthException: On permission or session issues
        :raises ZabbixAPIException: On errors returned by Zabbix or HTTP transport
        """
        self._req_id += 1
        if params is None:
            params = {}

        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._req_id,
        }

        headers = {
            "Content-Type": "application/json-rpc",
            "User-Agent": "JASS-JustAnotherSystemSniffer/1.0",
        }

        # Since Zabbix 6.4+, the auth token must be sent ONLY via the "Authorization: Bearer"
        # HTTP header; including an "auth" member in the JSON-RPC payload is rejected by the
        # server with "Invalid parameter '/': unexpected parameter 'auth'." For Zabbix versions
        # older than 6.4 (no Bearer header support), the token must also be included in the payload.
        # Methods that do not require authentication (e.g. apiinfo.version, user.login) must
        # never include an "auth" member at all, not even a null value.
        if auth_required:
            if not self.auth_token:
                raise ZabbixAuthException("No active auth token for authenticated method call.")
            headers["Authorization"] = f"Bearer {self.auth_token}"
            if self._api_major_version and self._api_major_version < 6.4:
                payload["auth"] = self.auth_token

        logger.debug(f"Sending JSON-RPC request: method={method}, id={self._req_id}")

        try:
            response = self.session.post(
                self.api_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.Timeout:
            logger.error(f"Timeout calling method {method} after {self.timeout}s.")
            raise ZabbixAPIException(f"Connection timeout ({self.timeout}s) for {method}")
        except requests.exceptions.SSLError as ssl_err:
            logger.error(f"SSL certificate verification error: {ssl_err}")
            raise ZabbixAPIException(f"SSL error connecting to {self.api_url}: {ssl_err}")
        except requests.exceptions.RequestException as req_err:
            logger.error(f"HTTP/Network error calling {method}: {req_err}")
            raise ZabbixAPIException(f"Network error connecting to Zabbix API: {req_err}")
        except ValueError as json_err:
            logger.error(f"JSON parsing error from Zabbix response: {json_err}")
            raise ZabbixAPIException("Server response is not valid JSON.")

        if "error" in data:
            err_obj = data["error"]
            err_msg = err_obj.get("message", "Unknown Zabbix API error")
            err_data = err_obj.get("data", "")
            err_code = err_obj.get("code")
            logger.error(f"Zabbix API error: {err_msg} - {err_data} (code {err_code})")
            if "Session terminated" in err_data or "Not authorized" in err_msg:
                raise ZabbixAuthException(err_msg, code=err_code, data=err_data)
            raise ZabbixAPIException(err_msg, code=err_code, data=err_data)

        if "result" not in data:
            raise ZabbixAPIException("Missing 'result' field in JSON-RPC response.")

        return data["result"]

    def __enter__(self) -> "ZabbixClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.logout()
