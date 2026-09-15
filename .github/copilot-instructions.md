# GitHub Copilot Instructions for JASS

You are working on **JASS (Just Another System Sniffer)**, a Python 3.10+ DevOps/SRE telemetry extraction framework that interfaces with **Zabbix API (6.0+)** to analyze Windows Server, Windows 10/11, and Hyper-V hosts and generate LLM-ready context payloads.

## Key Guidelines & Architecture

1. **Language & Style**:
   - Write all code, comments, docstrings, and documentation strictly in **English**.
   - Adhere to PEP 8 style, strict typing (`typing`), and Pydantic V2 schemas.

2. **Core Modules**:
   - `jass/core/client.py`: Zabbix JSON-RPC client (supports API token header + payload auth, automatic fallback to `user.login`).
   - `jass/core/models.py`: Pydantic V2 models for normalized telemetry output (`HostAnalysisPayload`).
   - `jass/core/base_module.py`: `BaseSystemSniffer` abstract base class for telemetry sniffers.
   - `jass/core/prompt_builder.py`: LLM prompt generator.
   - `jass/modules/windows_sniffer.py`: Windows & Hyper-V telemetry extraction, service state resolution, and role signature synthesis.
   - `jass/analyzers/zabbix_analyzer.py`: High-level orchestrator for host/group telemetry scanning and JSON exporting.
   - `jass/ui/app.py`: FastAPI server for the Web Dashboard.
   - `jass/cli.py`: Rich CLI interface.

3. **Extensibility**:
   - When adding new platform collectors (Linux, VMware, BSD), inherit from `BaseSystemSniffer`.
   - Keep data schemas immutable and validated via Pydantic.

4. **Testing**:
   - Always run the test suite: `python3 -m unittest discover -s tests -v`.
   - Maintain unit tests in `tests/` with mocked Zabbix JSON-RPC API responses.

Refer to `AGENTS.md` for in-depth design details and architectural patterns.
