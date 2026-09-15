# 🛡️ JASS - Just Another System Sniffer

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Zabbix API](https://img.shields.io/badge/Zabbix%20API-6.0%20LTS%20%7C%206.4%20%7C%207.0+-red.svg)](https://www.zabbix.com/documentation/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Dashboard-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**JASS (Just Another System Sniffer)** is an enterprise-grade DevOps/SRE telemetry framework and automation tool built in Python 3.10+. It interfaces natively with the **Zabbix API (6.0+)** to extract deep infrastructure telemetry from monitored hosts (**Microsoft Windows Server, Windows Desktop editions, and Hyper-V Virtualization Clusters**).

JASS generates structured, normalized JSON payloads (`[hostname]_analysis.json`) optimized as high-density context for Large Language Models (**LLMs** such as OpenAI GPT-4o, Anthropic Claude 3.5 Sonnet, DeepSeek, and Ollama) to autonomously classify business roles, audit system health, and diagnose infrastructure architectures.

The tool provides both an interactive **Rich CLI interface** and a modern **Web Dashboard (FastAPI + Tailwind CSS)** featuring an integrated **LLM Prompt Studio**.

---

## 🚀 Key Features

1. **Robust Zabbix API Integration (JSON-RPC 2.0)**:
   - Native support for **API Token authentication** (Bearer header & JSON-RPC payload auth for Zabbix 6.0+).
   - Seamless **fallback** to `user.login` session credentials when an API token is not configured.
   - Built-in request retries, timeout handling, and support for self-signed SSL certificates (`--insecure`).

2. **Comprehensive Telemetry Extraction**:
   - 📋 **[Host Inventory]**: Operating system, kernel version, hardware architecture, vendor, model, serial numbers, IP/MAC addresses, location, and Zabbix host tags.
   - ⚡ **[Performance Metrics]**: CPU utilization (%), core count, RAM metrics (Total, Used, Free, Utilization % with human-readable formatting), and system uptime.
   - 💾 **[Storage & Drives]**: Storage capacity, used/free space, and percent utilization across all filesystem volumes (C:, D:, E:, mountpoints).
   - ⚙️ **[Windows Services]**: System service states (`Running`, `Stopped`, `Paused`), startup types (`Automatic`, `Manual`, `Disabled`), and mapping of `service.info[*]` / `services[*]` item keys.
   - 🔮 **[Hyper-V Virtualization Telemetry]**: Detection of Hypervisor roles, guest VM enumeration, execution states, vCPU/RAM allocations, and replication telemetry.
   - 🔌 **[Remote Probe Execution (`script.execute`)]**: Live execution of remote diagnostic commands (e.g. PowerShell `Get-NetTCPConnection` for listening ports, network sockets, or active processes) executed directly via the Zabbix Agent.

3. **LLM Context Synthesis & Role Signatures**:
   - Automated heuristic signature matching for core Windows server workloads:
     - Active Directory Domain Controller / DNS / Kerberos
     - Microsoft SQL Server Database Engine & Agent
     - Internet Information Services (IIS) Web Server
     - Hyper-V Virtualization Host
     - Veeam Backup & Replication Repository
     - Microsoft Exchange Server / Remote Desktop Session Host
   - One-click export of structured JSON and AI prompt templates in standard Chat Completions format (`system` + `user` prompts).

4. **Interactive Web Dashboard**:
   - Responsive web UI built on FastAPI and Tailwind CSS.
   - Real-time host search, hostgroup filtering, live metrics visualization, storage gauge charts, service filtering, remote probe execution, and LLM Studio.

5. **Extensible Modular Architecture (OOP)**:
   - Abstract `BaseSystemSniffer` module allows developers and AI agents to easily add new telemetry collectors (e.g., Linux, VMware ESXi, Proxmox, Network Appliances).

---

## 📁 Repository Structure

```text
jass/
├── jass/
│   ├── core/
│   │   ├── client.py          # Zabbix 6.0+ JSON-RPC client (Token + user.login fallback)
│   │   ├── models.py          # Pydantic data schemas & JSON serialization
│   │   ├── base_module.py     # Base abstract class for system sniffers
│   │   └── prompt_builder.py  # LLM prompt templates and payload compiler
│   ├── modules/
│   │   └── windows_sniffer.py # Dedicated Windows & Hyper-V sniffer module
│   ├── analyzers/
│   │   └── zabbix_analyzer.py # High-level orchestrator for host/group scanning
│   ├── ui/
│   │   ├── app.py             # FastAPI Web Dashboard application & REST endpoints
│   │   └── templates/
│   │       └── index.html     # Responsive Web Dashboard (Tailwind CSS + JS)
│   ├── cli.py                 # Rich CLI command-line interface
│   └── __init__.py
├── tests/
│   ├── test_client.py         # Unit tests for ZabbixClient
│   └── test_sniffer.py        # Unit tests for WindowsSniffer & telemetry parsing
├── run.py                     # Main application entry point (CLI & Web UI launcher)
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variables template
├── AGENTS.md                  # Comprehensive instructions & architecture guide for AI agents
├── .github/
│   └── copilot-instructions.md# GitHub Copilot agent guidelines
└── README.md
```

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Access to a Zabbix Server or Proxy instance (Zabbix 6.0 LTS, 6.4, 7.0+ recommended)

### 1. Clone the repository
```bash
git clone https://github.com/tulonbaar/jass.git
cd jass
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` with your Zabbix API credentials:
```env
ZABBIX_URL=http://zabbix.corp.local/api_jsonrpc.php
ZABBIX_API_TOKEN=your_zabbix_api_token_here

# Or fallback to username/password:
# ZABBIX_USER=Admin
# ZABBIX_PASSWORD=zabbix

ZABBIX_TIMEOUT=15
ZABBIX_VERIFY_SSL=true
JASS_OUTPUT_DIR=./analysis_reports
```

---

## 💻 CLI Usage

### 1. Analyze a Single Host:
```bash
python run.py --url "http://zabbix.corp.local/zabbix" --token "secret_api_token" --host "WIN-SRV-SQL01"
```
The output is automatically saved to `WIN-SRV-SQL01_analysis.json`.

### 2. Analyze an Entire Hostgroup:
```bash
python run.py --url "http://zabbix.corp.local/zabbix" --token "secret_api_token" --hostgroup "Windows Servers" -o ./reports
```

### 3. Analyze with Remote Diagnostic Probe (`script.execute`):
```bash
python run.py --url "http://zabbix.corp.local/zabbix" --token "secret_api_token" --host "WIN-SRV-HV01" --remote-probe
```

### 4. Generate LLM Analysis Prompt:
```bash
python run.py --url "http://zabbix.corp.local/zabbix" --token "secret_api_token" --host "WIN-SRV-DC01" --prompt --print-prompt
```

### 5. List Available Hosts and Hostgroups:
```bash
python run.py --url "http://zabbix.corp.local/zabbix" --token "secret_api_token" --list-hosts
python run.py --url "http://zabbix.corp.local/zabbix" --token "secret_api_token" --list-groups
```

---

## 🌐 Web Dashboard (GUI)

Start the interactive web dashboard with:
```bash
python run.py --serve --port 8080
```
Open your browser at: **`http://localhost:8080`**

### Dashboard Capabilities:
- Configure and test Zabbix API connection settings on the fly.
- Live tree exploration of hostgroups and instant host searching.
- Real-time gauge metrics for CPU, RAM, and disk volume utilization.
- Interactive service status table with search and filtering (`Running`, `Stopped`).
- Hyper-V guest virtual machine inspection.
- Remote PowerShell network socket probe execution with single-click output.
- **LLM Studio**: Instant generation of optimized LLM prompts with copy-to-clipboard functionality.

---

## 📊 Sample Output Schema (`[host]_analysis.json`)

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
    "hyperv_vms_count": 0
  }
}
```

---

## 🧪 Testing

Run the full test suite using Python's built-in `unittest` framework:
```bash
python -m unittest discover -s tests -v
```

---

## 🤖 Instructions for AI Agents

Detailed architecture documentation, development guidelines, schema definitions, and module extension patterns for AI agents (GitHub Copilot, Claude, Cursor, Devin, etc.) are available in [AGENTS.md](./AGENTS.md) and [.github/copilot-instructions.md](./.github/copilot-instructions.md).

---

## 📄 License

This project is licensed under the MIT License.
