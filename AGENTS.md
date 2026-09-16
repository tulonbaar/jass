# 🤖 Instructions for AI Agents Working on JASS

This document provides architectural context, domain knowledge, coding guidelines, and extension patterns for AI agents (e.g., GitHub Copilot, Claude, Cursor, Devin) contributing to **JASS (Just Another System Sniffer)**.

---

## 🎯 Repository Purpose & Mission

**JASS** is an extensible DevOps/SRE telemetry extraction framework written in Python 3.10+. It connects to a **Zabbix Server / Proxy (6.0+)** via JSON-RPC, collects and normalizes deep diagnostic data from monitored hosts (currently focused on Microsoft Windows and Hyper-V), and compiles structured, high-density JSON payloads (`HostAnalysisPayload`) alongside prompt templates for Large Language Models (LLMs).

### Primary Use Case:
Enterprise environments often monitor hundreds of Windows virtual and physical machines whose exact business purpose, running workloads, or technical roles are poorly documented. JASS extracts telemetry (OS inventory, performance counters, active services, storage allocations, guest VMs, listening network sockets) and transforms it into structured context that LLMs use to autonomously classify server roles (e.g., "Primary Active Directory Domain Controller with DNS role", "Production MS SQL Server 2022 Instance with 128GB RAM").

---

## 🏗️ Architecture & Component Layout

The codebase follows a modular Object-Oriented Architecture with strict separation of concerns:

```text
jass/
├── jass/
│   ├── core/
│   │   ├── client.py          # ZabbixClient: JSON-RPC 2.0 client with Token & user.login fallback
│   │   ├── models.py          # Pydantic models (V2): HostAnalysisPayload, Metrics, Services, Hyper-V
│   │   ├── base_module.py     # BaseSystemSniffer: Abstract base class for platform telemetry sniffers
│   │   └── prompt_builder.py  # LLMPromptBuilder: System & user prompt templates for LLMs
│   ├── modules/
│   │   └── windows_sniffer.py # WindowsSniffer: Windows Server, Windows 10/11 & Hyper-V sniffer
│   ├── analyzers/
│   │   └── zabbix_analyzer.py # ZabbixAnalyzer: High-level orchestrator for host/group telemetry scanning
│   ├── ui/
│   │   ├── app.py             # FastAPI application and REST endpoints for the Web Dashboard
│   │   └── templates/
│   │       └── index.html     # Single-page Web Dashboard (Tailwind CSS, dark mode, vertical tabs)
│   ├── cli.py                 # Rich CLI command-line interface with argument parser
│   └── __init__.py            # Package root exports
├── tests/
│   ├── test_client.py         # Unit tests for Zabbix JSON-RPC communication and error handling
│   └── test_sniffer.py        # Unit tests for metric parsing, service mapping, and prompt synthesis
├── run.py                     # Entry point (CLI & Web UI)
├── requirements.txt           # Dependency manifest
└── .env.example               # Environment variables configuration template
```

---

## 🔑 Core Components Breakdown

### 1. `jass.core.client.ZabbixClient`
- **Protocol**: JSON-RPC 2.0 over HTTP/HTTPS.
- **Authentication**:
  - **Option 1 (Preferred)**: Zabbix API Token passed in both HTTP headers (`Authorization: Bearer <token>`) and the JSON-RPC `"auth"` field.
  - **Option 2 (Fallback)**: `user.login` RPC call (using `username` or legacy `user` parameter depending on Zabbix version).
- **Session Management**: Uses `requests.Session` with custom `HTTPAdapter` configured with `urllib3.util.Retry` for connection resiliency.
- **Error Handling**: Raises `ZabbixAPIException` (with API error code, message, and details) and `ZabbixAuthException`.

### 2. `jass.core.models`
- Built on **Pydantic V2**.
- Models include: `HostInventory`, `DriveMetric`, `HostMetrics`, `WindowsService`, `HyperVGuestVM`, `HyperVData`, `RemoteExecutionResult`, `HostAnalysisPayload`.
- All timestamps use ISO 8601 UTC format.
- Output serialization helper: `payload.to_llm_json(indent=2)` and `payload.to_dict()`.

### 3. `jass.core.base_module.BaseSystemSniffer`
- Abstract base class inheriting `abc.ABC`.
- Defines the required contract for all platform sniffers:
  - `collect_inventory(host_id, host_raw) -> HostInventory`
  - `collect_metrics(host_id, items) -> HostMetrics`
  - `collect_services(host_id, items) -> List[Any]`
  - `collect_virtualization_data(host_id, items) -> HyperVData`
  - `execute_remote_probe(host_id, script_name_or_cmd, probe_key) -> RemoteExecutionResult`
  - `analyze_host(host_identifier, run_remote_probe, script_name, probe_key) -> HostAnalysisPayload`

### 4. `jass.modules.windows_sniffer.WindowsSniffer`
- Specializes `BaseSystemSniffer` for Windows and Hyper-V.
- Normalizes metric keys across multiple Zabbix agent templates (`Template OS Windows by Zabbix agent`, `Windows by Zabbix agent active`, WMI, `perf_counter`, `perf_counter_en`).
- Contains heuristics for heuristic role detection in `ROLE_SIGNATURES`:
  - Active Directory, MS SQL Server, IIS, Hyper-V, Veeam Backup, Exchange, Remote Desktop.
- Translates numerical service state codes (e.g. `0 -> Running`, `6 -> Stopped`) and startup types (`0 -> Automatic`, `1 -> Automatic (Delayed)`, `2 -> Manual`, `3 -> Disabled`).

### 5. `jass.analyzers.zabbix_analyzer.ZabbixAnalyzer`
- High-level coordinator that handles host discovery, hostgroup batch scanning, multi-threaded or sequential data extraction, and JSON file export.
- Supports filtering by host status (monitored vs unmonitored).

### 6. `jass.core.prompt_builder.LLMPromptBuilder`
- Generates system and user prompts designed for standard LLM Chat Completion APIs (`OpenAI`, `Anthropic`, `Ollama`).
- Pre-structures the prompt with server identity, inventory, core resources, disks, top services, virtualization flags, and remote probe outputs.

### 7. `jass.core.probes.PROBE_CATALOG`
- A registry of named, reusable remote diagnostic probes (`ProbeDefinition`: key, Zabbix script name,
  PowerShell command, parser function). Backs the Probe / Remote Execution mechanism - see the
  "How the Probe / Remote Execution mechanism works" section of [README.md](README.md).
- `WindowsSniffer.execute_remote_probe()` auto-creates the corresponding Zabbix script (`script.create`)
  the first time a probe key is used, then runs it via `script.execute` and parses the result.
- Built-in probes: `listening_ports`, `hardware_inventory` (serial number/MAC, CPUs, RAM, NICs, Disks via WMI/CIM),
  `installed_applications` (Uninstall registry keys), `event_log_errors` (System/Application logs,
  last 24h), `disk_content_scan` (top-level folders per drive, flags non-standard ones).

---

## 🛠️ How to Extend JASS

When adding new features or modules, follow these established design patterns:

### Adding a New Remote Probe (e.g., a new diagnostic script)
1. Open `jass/core/probes.py`.
2. Write a parser function `parse_<name>(output: str) -> Any` that turns the raw agent stdout into
   structured JSON (use `_safe_json_loads()` to tolerate PowerShell noise around the JSON payload).
3. Add a `ProbeDefinition` entry to `PROBE_CATALOG` with a unique key, the Zabbix script display name
   JASS should create/look up, the PowerShell one-liner to run, and the parser.
4. That's it - the CLI (`--probe`, `--list-probes`), the Web UI probe dropdown, and
   `WindowsSniffer.execute_remote_probe()` all read from `PROBE_CATALOG` automatically; no other code
   needs to change.
5. If the probe should enrich `HostInventory` or another model (like `hardware_inventory` does today
   via `WindowsSniffer._merge_probe_into_inventory`), add a small merge step in
   `windows_sniffer.py::analyze_host()`.

### Adding a New Platform Sniffer (e.g., Linux / VMware ESXi)
1. Create a new module in `jass/modules/` (e.g., `linux_sniffer.py`).
2. Subclass `BaseSystemSniffer` from `jass.core.base_module`.
3. Implement all abstract methods:
   - `collect_inventory`: Extract Linux OS release, architecture, interfaces, kernel.
   - `collect_metrics`: Parse `system.cpu.util`, `vm.memory.util`, `vfs.fs.size[/,used]`, `system.uptime`.
   - `collect_services`: Parse `systemd.unit.info[*]`, `proc.num[*]`.
   - `collect_virtualization_data`: Detect KVM / Docker / Podman containers.
   - `execute_remote_probe`: Run Linux shell scripts via `script.execute` (e.g. `ss -tulpn`).
4. Update `ZabbixAnalyzer` to auto-detect the OS from host inventory or tags and route to the corresponding sniffer.
5. Add unit tests in `tests/test_linux_sniffer.py`.

### Adding New Workload Signatures
To add detection for new server workloads (e.g., Apache Tomcat, Oracle DB, Kubernetes agent, Prometheus node exporter):
1. Open `jass/modules/windows_sniffer.py` (or the relevant platform sniffer).
2. Append to `ROLE_SIGNATURES`:
   ```python
   "Apache Tomcat Application Server": {
       "services": ["tomcat", "tomcat9", "tomcat10"],
       "items": ["tomcat", "catalina"],
       "ports": [8080, 8443],
   }
   ```
3. Update `_detect_workload_signatures()` logic if complex multi-attribute conditions are needed.

### Adding Direct LLM API Execution
If asked to enable direct LLM execution (e.g. automatically querying OpenAI / Anthropic / Ollama from CLI or Web UI):
1. Create `jass/core/llm_client.py`.
2. Implement providers using standard REST / SDK calls with configurable model names, base URLs, and API keys.
3. Add a `--query-llm` flag to `jass/cli.py` and a `/api/analyze-llm` endpoint to `jass/ui/app.py`.

---

## 🗺️ Roadmap / Planned Extensions

- **Network traffic analysis (deferred, not yet implemented)**: per-host analysis of *who talks to
  whom* - active TCP/UDP connections (not just listeners), remote endpoints contacted, and which
  services listen on which ports. Likely design: a new `network_traffic_scan` probe
  (`Get-NetTCPConnection` without the `-State Listen` filter, plus reverse-DNS/ASN enrichment done
  JASS-side) feeding a new `NetworkConnection` model and a dedicated `collect_network_topology()`
  method. Explicitly scoped as a later phase by the project owner - do not start without an explicit
  request.
- **Disk content analysis**: the `disk_content_scan` probe currently only lists top-level folder
  names per drive and flags non-standard ones. Follow-up: recursive scanning with size/age hints,
  and heuristic detection of known application/database footprints (e.g. `*.mdf`/`*.ldf` -> SQL
  Server, `*.vhdx` -> Hyper-V storage, `Program Files\<vendor>` -> installed vendor software).

---

## 🧪 Testing & Quality Assurance

- All test cases reside in `tests/`.
- Tests use Python's standard `unittest` module and mock the `ZabbixClient` network layer to ensure tests run offline without a live Zabbix instance.
- **Run all tests**:
  ```bash
  python3 -m unittest discover -s tests -v
  ```
- Always verify that all tests pass before completing tasks.

---

## 📜 Development Conventions

1. **Python Compatibility**: Python 3.10+ (use modern type annotations `list[str] | None` or `Optional[List[str]]`).
2. **Type Hinting**: All public methods and classes must have complete type hints.
3. **Docstrings**: Use clear Google-style or Sphinx-style docstrings in English for all public functions, classes, and methods.
4. **Data Integrity**: Never modify raw Zabbix API item keys destructively; preserve raw keys in `.raw_attributes` or `.raw_items_sample` for debugging.
5. **No Hardcoded Secrets**: Always load credentials from environment variables (`.env`) or CLI arguments.
