# 🛡️ JASS - Just Another System Sniffer

**JASS (Just Another System Sniffer)** to zaawansowany framework i narzędzie telemetryczne klasy DevOps / SRE napisane w Pythonie 3.10+, integrujące się z **Zabbix API (6.0+)**. 

Głównym celem aplikacji jest głębokie badanie monitorowanych maszyn (**Microsoft Windows Server, Windows 10/11, Hyper-V Clusters**) i generowanie ustrukturyzowanych plików JSON (`[nazwa_hosta]_analysis.json`), które stanowią gotowy wsad (context payload) dla modeli językowych (**LLM**: OpenAI GPT-4o, Claude 3.5 Sonnet, Ollama, DeepSeek itp.) w celu automatycznej analizy przeznaczenia biznesowego serwerów, klasyfikacji ról i audytu wydajności.

Aplikacja oferuje zarówno bogaty **interfejs CLI** z kolorowymi tabelami i paskami postępu, jak i nowoczesny **Web Dashboard (FastAPI + Tailwind)** z wbudowanym **LLM Studio**.

---

## 🚀 Kluczowe Funkcjonalności

1. **Nowoczesna integracja z Zabbix API (JSON-RPC 2.0)**:
   - Natywna obsługa **API Token** (rekomendowana od Zabbix 6.0+) z nagłówkiem `Authorization: Bearer <token>` oraz `auth` w payloadzie.
   - Automatyczny **fallback** na logowanie użytkownik/hasło (`user.login`) w przypadku braku tokena.
   - Obsługa timeoutów, automatycznych ponowień (retry backoff) i certyfikatów self-signed (`--insecure`).

2. **Głębokie zbieranie danych telemetrycznych**:
   - 📋 **[Host Inventory]**: System operacyjny, wersja jądra, architektura, producent, model sprzętu, numer seryjny, adresy MAC i IP, lokalizacja, tagi Zabbix.
   - ⚡ **[Key Performance Metrics]**: Utylizacja CPU (%), rdzenie procesora, pamięć RAM (Total, Used, Free, % w formacie czytelnym dla człowieka), Uptime systemu.
   - 💾 **[Storage & Drives]**: Pojemność, wolne/zajęte miejsce i procentowe obciążenie dla wszystkich wolumenów (C:, D:, E: itp.).
   - ⚙️ **[Windows Services]**: Status usług systemowych (`Running`, `Stopped`, `Paused`), typ uruchomienia (`Automatic`, `Manual`, `Disabled`) oraz mapowanie kluczy `service.info[*]`.
   - 🔮 **[Hyper-V Telemetry]**: Wykrywanie roli Hypervisora, lista zwirtualizowanych maszyn gości (Guest VMs), ich stan działania, alokacja vCPU/RAM i replikacja.
   - 🔌 **[Remote Execution (`script.execute`)]**: Zdalne wykonywanie skryptów PowerShell (np. `Get-NetTCPConnection` dla nasłuchujących portów) bezpośrednio na agencie przez Zabbix API.

3. **LLM Studio & Prompt Engineering**:
   - Automatyczna synteza sygnatur ról (np. Active Directory DC, MS SQL Server, IIS Web Server, Hyper-V Node, Backup Repository).
   - Generowanie gotowych promptów dla ChatGPT, Claude lub lokalnych modeli Ollama w formacie Chat Completions.

4. **Wbudowany Web Dashboard**:
   - Podgląd hostów, grup, live telemetry, wykresy zajętości dysków, tabela usług z filtrami, terminal zdalnej sondy i 1-click eksport do LLM.

5. **Modułowa architektura OOP**:
   - `BaseSystemSniffer` umożliwia łatwe dobudowywanie kolejnych modułów (np. Linux Sniffer, VMware ESXi Sniffer, Network Appliances).

---

## 📁 Struktura Projektu

```text
jass/
├── jass/
│   ├── core/
│   │   ├── client.py          # Klient JSON-RPC Zabbix 6.0+ (Token + Fallback login)
│   │   ├── models.py          # Pydantic modele telemetryczne i JSON schema
│   │   ├── base_module.py     # Klasa bazowa BaseSystemSniffer
│   │   └── prompt_builder.py  # Kompilator promptów dla modeli LLM
│   ├── modules/
│   │   └── windows_sniffer.py # Dedykowany sniffer Windows & Hyper-V
│   ├── analyzers/
│   │   └── zabbix_analyzer.py # Główny orkiestrator analizy hostów i grup
│   ├── ui/
│   │   ├── app.py             # Serwer Web Dashboard (FastAPI + Uvicorn)
│   │   └── templates/
│   │       └── index.html     # Nowoczesny Dashboard (Tailwind CSS + JS)
│   ├── cli.py                 # Interfejs wiersza poleceń z Rich UI
│   └── __init__.py
├── tests/
│   ├── test_client.py         # Testy jednostkowe klienta Zabbix
│   └── test_sniffer.py        # Testy parsowania metryk, usług i Hyper-V
├── run.py                     # Główny punkt wejściowy aplikacji
├── requirements.txt           # Zależności Python
├── .env.example               # Przykładowa konfiguracja środowiskowa
└── README.md
```

---

## 🛠️ Instalacja i Wymagania

### Wymagania:
- Python 3.10 lub nowszy
- Dostęp do instancji Zabbix 6.0 LTS, 6.4, 7.0+ (lub 5.4+)

### Krok 1: Klonowanie / przejście do katalogu
```bash
cd /home/tulonbaar/__repos/jass
```

### Krok 2: Instalacja zależności
```bash
pip install -r requirements.txt
```

### Krok 3: Konfiguracja zmiennych środowiskowych (opcjonalnie)
Możesz utworzyć plik `.env` na podstawie `.env.example`:
```bash
cp .env.example .env
```
Wypełnij w nim dane:
```env
ZABBIX_URL=http://zabbix.corp.local/api_jsonrpc.php
ZABBIX_API_TOKEN=twoj_zabbix_api_token
```

---

## 💻 Użycie CLI (Wiersz Poleceń)

### 1. Badanie pojedynczego hosta Windows:
```bash
python run.py --url "http://192.168.1.100/zabbix" --token "secret_token" --host "WIN-SRV-SQL01"
```
Wynik zostanie zapisany automatycznie do pliku `WIN-SRV-SQL01_analysis.json`.

### 2. Badanie grupy hostów (Hostgroup):
```bash
python run.py --url "http://192.168.1.100/zabbix" --token "secret_token" --hostgroup "Windows servers" -o ./reports
```

### 3. Badanie z wykonaniem zdalnej sondy PowerShell (`script.execute`):
```bash
python run.py --url "http://192.168.1.100/zabbix" --token "secret_token" --host "WIN-SRV-HV01" --remote-probe
```

### 4. Generowanie promptu dla LLM:
```bash
python run.py --url "http://192.168.1.100/zabbix" --token "secret_token" --host "WIN-SRV-DC01" --prompt --print-prompt
```

### 5. Wypisanie listy dostępnych hostów i grup:
```bash
python run.py --url "http://192.168.1.100/zabbix" --token "secret_token" --list-hosts
python run.py --url "http://192.168.1.100/zabbix" --token "secret_token" --list-groups
```

---

## 🌐 Uruchomienie Web Dashboard (Interfejs Graficzny)

Aby uruchomić interaktywny interfejs graficzny:
```bash
python run.py --serve --port 8080
```
Następnie otwórz przeglądarkę pod adresem: **`http://localhost:8080`**

W interfejsie graficznym możesz:
- Wprowadzić lub zmienić dane połączenia Zabbix API.
- Przeglądać drzewo grup i wyszukiwać maszyny w czasie rzeczywistym.
- Podglądać wskaźniki CPU, RAM, wolumenów dyskowych oraz listę usług z podziałem na Running / Stopped.
- Badać środowiska Hyper-V z listą maszyn wirtualnych.
- Uruchamiać sondy PowerShell jednym kliknięciem.
- Generować i kopiować gotowe prompty dla modeli AI w zakładce **LLM Studio**.

---

## 📊 Przykładowa Struktura Pliku Wyjściowego JSON (`[host]_analysis.json`)

```json
{
  "schema_version": "1.0.0",
  "collector": "JASS - Just Another System Sniffer (Windows/Hyper-V Analyzer)",
  "collected_at": "2026-09-15T18:00:00Z",
  "host_id": "10452",
  "host_name": "WIN-SRV-SQL01",
  "visible_name": "MS SQL Production Node",
  "status": "Monitored",
  "host_groups": ["Windows Servers", "Database Cluster"],
  "tags": [
    {"tag": "Environment", "value": "Production"},
    {"tag": "Tier", "value": "Critical"}
  ],
  "interfaces": [
    {
      "interfaceid": "102",
      "ip": "10.20.30.55",
      "dns": "sql01.corp.local",
      "port": "10050",
      "type": 1,
      "main": 1
    }
  ],
  "inventory": {
    "os": "Windows Server 2022 Datacenter",
    "hardware": "Dell PowerEdge R750",
    "serial_number": "DELL-987654321",
    "vendor": "Dell Inc.",
    "model": "PowerEdge R750",
    "ip_addresses": ["10.20.30.55"]
  },
  "metrics": {
    "cpu_utilization_percent": 24.5,
    "cpu_cores": 32,
    "memory_total_bytes": 137438953472,
    "memory_total_formatted": "128.00 GB",
    "memory_used_bytes": 103079215104,
    "memory_used_formatted": "96.00 GB",
    "memory_utilization_percent": 75.0,
    "uptime_formatted": "45d 12h 30m 10s",
    "drives": [
      {
        "fs_name": "C:",
        "total_formatted": "200.00 GB",
        "used_formatted": "60.00 GB",
        "free_formatted": "140.00 GB",
        "used_percent": 30.0,
        "free_percent": 70.0
      },
      {
        "fs_name": "D:",
        "total_formatted": "2.00 TB",
        "used_formatted": "1.40 TB",
        "free_formatted": "600.00 GB",
        "used_percent": 70.0,
        "free_percent": 30.0
      }
    ]
  },
  "windows_services": [
    {"name": "MSSQLSERVER", "display_name": "SQL Server (MSSQLSERVER)", "state": "Running", "startup_type": "Automatic"},
    {"name": "SQLSERVERAGENT", "display_name": "SQL Server Agent", "state": "Running", "startup_type": "Automatic"}
  ],
  "hyperv": {
    "is_hyperv_host": false,
    "virtual_machines_count": 0,
    "guest_vms": []
  },
  "llm_context_hints": {
    "detected_signatures": ["Microsoft SQL Server Database Engine"],
    "running_services_count": 28,
    "total_storage_drives": 2
  }
}
```

---

## 🤖 Prompt dla Modeli LLM

Moduł `LLMPromptBuilder` zawiera wyprofilowany system prompt, który instruuje model LLM do sporządzenia profesjonalnego audytu biznesowego:

1. 🎯 **Główna rola i przeznaczenie biznesowe serwera**.
2. 🧩 **Wykryty stos technologiczny i kluczowe komponenty**.
3. ⚡ **Ocena obciążenia i alokacji zasobów (Capacity & Sizing)**.
4. 🛡️ **Wnioski dotyczące bezpieczeństwa i konfiguracji**.
5. 💡 **Rekomendacje architektoniczne i optymalizacyjne**.

---

## 🧩 Rozszerzalność (Nowe Moduły i Systemy)

Architektura oparta o `BaseSystemSniffer` pozwala na dodanie kolejnego systemu w 3 prostych krokach:
1. Utwórz plik w `jass/modules/linux_sniffer.py`.
2. Zaimplementuj klasę dziedziczącą po `BaseSystemSniffer`.
3. Zarejestruj sniffer w `ZabbixAnalyzer`.
