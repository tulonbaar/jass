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
    """Baza dla wyjątków związanych z zapytaniami do Zabbix API."""

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
    """Wyjątek rzucany przy niepowodzeniu autentykacji."""
    pass


class ZabbixClient:
    """
    Zaawansowany klient JSON-RPC dla Zabbix API (kompatybilny z Zabbix 6.0+).
    
    Obsługuje:
    - Autentykację za pomocą API Token (Bearer Token / auth token)
    - Fallback na tradycyjne logowanie user/password (metoda user.login)
    - Automatyczne ponawianie zapytań (Retry logic) i obsługę timeoutów
    - Wsparcie dla self-signed certyfikatów SSL
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
        Inicjalizacja klienta Zabbix API.

        :param url: Bazowy adres URL instancji Zabbix (np. https://zabbix.local lub https://zabbix.local/api_jsonrpc.php)
        :param api_token: API Token Zabbixa (Zabbix 5.4 / 6.0+)
        :param username: Nazwa użytkownika (używana w przypadku braku tokena)
        :param password: Hasło użytkownika (używane w przypadku braku tokena)
        :param timeout: Czas oczekiwania na odpowiedź w sekundach
        :param verify_ssl: Weryfikacja certyfikatu SSL serwera
        :param max_retries: Maksymalna liczba prób ponowienia przy błędach sieciowych
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

    @staticmethod
    def _normalize_api_url(url: str) -> str:
        """Normalizuje podany adres URL do pełnej ścieżki api_jsonrpc.php."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
        
        if not url.endswith("/api_jsonrpc.php"):
            if url.endswith("/"):
                url += "api_jsonrpc.php"
            else:
                url += "/api_jsonrpc.php"
        return url

    @property
    def is_authenticated(self) -> bool:
        """Zwraca True, jeśli klient posiada aktywny token autentykacji."""
        return bool(self.auth_token)

    def connect(self) -> str:
        """
        Nawiązuje połączenie z Zabbix API, pobiera wersję serwera i przeprowadza autentykację.
        
        :return: Zwraca wersję Zabbix API (np. '6.4.12')
        :raises ZabbixAuthException: Przy błędzie autentykacji
        :raises ZabbixAPIException: Przy błędzie komunikacji z API
        """
        logger.info(f"Łączenie z Zabbix API pod adresem: {self.api_url}")
        
        # 1. Sprawdzenie wersji API (nie wymaga autoryzacji)
        self._api_version = self.get_version()
        logger.info(f"Wykryto Zabbix API w wersji: {self._api_version}")

        # 2. Autoryzacja
        if self.api_token:
            logger.info("Używanie API Tokena do autoryzacji.")
            self.auth_token = self.api_token
            # Test tokena poprzez lekkie zapytanie
            try:
                self.call("user.get", {"output": ["userid", "username"]})
                logger.info("Autoryzacja za pomocą API Tokena zakończona sukcesem.")
                return self._api_version
            except ZabbixAPIException as exc:
                logger.warning(f"Test API Tokena nie powiódł się ({exc}). Próba fallbacku...")
                if not (self.username and self.password):
                    raise ZabbixAuthException(f"Nieprawidłowy API Token: {exc.message}")

        if self.username and self.password:
            logger.info(f"Przeprowadzanie logowania dla użytkownika '{self.username}' (user.login)...")
            self._login(self.username, self.password)
            return self._api_version

        raise ZabbixAuthException("Brak wymaganych danych uwierzytelniających (wymagany API Token lub username/password).")

    def get_version(self) -> str:
        """Wywołuje metodę `apiinfo.version` w celu pobrania wersji Zabbix API."""
        resp = self.call("apiinfo.version", {}, auth_required=False)
        if isinstance(resp, str):
            return resp
        raise ZabbixAPIException(f"Nieoczekiwany format wersji API: {resp}")

    def _login(self, username: str, password: str) -> str:
        """
        Logowanie za pomocą metody `user.login`.
        Kompatybilne z Zabbix 6.0+ (pole 'username') oraz starszymi wersjami (pole 'user').
        """
        params_v6 = {"username": username, "password": password}
        try:
            token = self.call("user.login", params_v6, auth_required=False)
            self.auth_token = str(token)
            logger.info("Zalogowano pomyślnie za pomocą user.login.")
            return self.auth_token
        except ZabbixAPIException as e:
            # Fallback dla starszych wersji parametrów
            try:
                params_legacy = {"user": username, "password": password}
                token = self.call("user.login", params_legacy, auth_required=False)
                self.auth_token = str(token)
                logger.info("Zalogowano pomyślnie (legacy param: user).")
                return self.auth_token
            except ZabbixAPIException:
                raise ZabbixAuthException(f"Błąd logowania Zabbix user.login: {e.message}")

    def logout(self) -> bool:
        """Wylogowanie sesji jeśli logowano się loginem/hasłem."""
        if self.auth_token and not self.api_token:
            try:
                self.call("user.logout", {})
                self.auth_token = None
                logger.info("Wylogowano sesję Zabbix API.")
                return True
            except Exception as e:
                logger.debug(f"Błąd podczas wylogowywania: {e}")
        return False

    def call(
        self,
        method: str,
        params: Optional[Union[Dict[str, Any], List[Any]]] = None,
        auth_required: bool = True,
    ) -> Any:
        """
        Wykonuje zapytanie JSON-RPC 2.0 do Zabbix API.

        :param method: Nazwa metody Zabbix API (np. host.get, item.get)
        :param params: Parametry przekazywane do metody
        :param auth_required: Czy zapytanie wymaga autoryzacji
        :return: Wynik z pola 'result' odpowiedzi JSON-RPC
        :raises ZabbixAuthException: Przy problemach z uprawnieniami/sesją
        :raises ZabbixAPIException: Przy błędach zwróconych przez Zabbixa lub HTTP
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

        # W Zabbix 6.0+ token może być w polu "auth" lub nagłówku Bearer
        if auth_required:
            if not self.auth_token:
                raise ZabbixAuthException("Brak aktywnego tokena autoryzacji dla zapytania wymagającego uwierzytelnienia.")
            payload["auth"] = self.auth_token
            headers["Authorization"] = f"Bearer {self.auth_token}"
        else:
            payload["auth"] = None

        logger.debug(f"Wysyłanie zapytania JSON-RPC: method={method}, id={self._req_id}")

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
            logger.error(f"Timeout podczas wywołania metody {method} po {self.timeout}s.")
            raise ZabbixAPIException(f"Przekroczono limit czasu połączenia ({self.timeout}s) dla {method}")
        except requests.exceptions.SSLError as ssl_err:
            logger.error(f"Błąd weryfikacji SSL: {ssl_err}")
            raise ZabbixAPIException(f"Błąd certyfikatu SSL podczas łączenia z {self.api_url}: {ssl_err}")
        except requests.exceptions.RequestException as req_err:
            logger.error(f"Błąd HTTP/sieci podczas wywołania {method}: {req_err}")
            raise ZabbixAPIException(f"Błąd połączenia z Zabbix API: {req_err}")
        except ValueError as json_err:
            logger.error(f"Błąd parsowania JSON z odpowiedzi Zabbix API: {json_err}")
            raise ZabbixAPIException("Odpowiedź serwera nie jest poprawnym obiektem JSON.")

        if "error" in data:
            err_obj = data["error"]
            err_msg = err_obj.get("message", "Nieznany błąd Zabbix API")
            err_data = err_obj.get("data", "")
            err_code = err_obj.get("code")
            logger.error(f"Zabbix API zwrócił błąd: {err_msg} - {err_data} (kod {err_code})")
            if "Session terminated" in err_data or "Not authorized" in err_msg:
                raise ZabbixAuthException(err_msg, code=err_code, data=err_data)
            raise ZabbixAPIException(err_msg, code=err_code, data=err_data)

        if "result" not in data:
            raise ZabbixAPIException("Brak pola 'result' w odpowiedzi JSON-RPC.")

        return data["result"]

    def __enter__(self) -> "ZabbixClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.logout()
