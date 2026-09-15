# Hyper-V VMs via PowerShell - Zabbix Template

This directory contains the reference Zabbix template and PowerShell collector used by JASS's
Hyper-V parser (`WindowsSniffer.collect_virtualization_data()` in
[jass/modules/windows_sniffer.py](../../jass/modules/windows_sniffer.py)). It provides much richer
per-VM telemetry than generic Hyper-V performance-counter templates: VM state, uptime, vCPU/RAM
usage & demand, MAC/IP address, and checkpoint (snapshot) health.

## Files

| File | Purpose |
|---|---|
| `zbx-hyperv.ps1` | PowerShell collector script. Run via Zabbix Agent 2 UserParameters with `lld` (low-level discovery of VM names) or `full` (per-VM metrics as a single JSON blob) arguments. Uses `Get-VM` / `Get-VMSnapshot` / `Get-VMNetworkAdapter`. |
| `hyperv.conf` | Zabbix Agent 2 UserParameter definitions. Deploy to `C:\Zabbix\zabbix_agent2.d\` on the Hyper-V host, referencing the script path `C:\zabbix\scripts\zbx-hyperv.ps1`. |
| `zbx_export_templates_hyperv.yaml` | Zabbix template "Hyper-V VMs via PowerShell" (import via *Data collection → Templates → Import*). Defines the master item `hyperv.metrics`, LLD rule `hyperv.discovery`, and dependent item prototypes `hyperv.vm.<metric>["{#VM.NAME}"]`. |

## Deployment steps

1. Copy `zbx-hyperv.ps1` to `C:\zabbix\scripts\` on the Hyper-V host.
2. Copy `hyperv.conf` to `C:\Zabbix\zabbix_agent2.d\` and restart the `Zabbix Agent 2` service.
3. Import `zbx_export_templates_hyperv.yaml` into Zabbix (*Data collection → Templates → Import*).
4. Link the imported template ("Hyper-V VMs via PowerShell") to the Hyper-V host(s) in Zabbix.
5. Wait for the LLD rule (`hyperv.discovery`, default interval 1h) to run once, creating the
   per-VM dependent items automatically.
6. Run a JASS analysis against the host - `collect_virtualization_data()` will detect the
   `hyperv.vm.*["VMNAME"]` keys automatically and populate `hyperv.guest_vms[]` in the output JSON.

## Item key -> JASS field mapping

| Zabbix item key | `HyperVGuestVM` field |
|---|---|
| `hyperv.vm.state["{#VM.NAME}"]` | `state` (mapped from the `Microsoft.HyperV.PowerShell.VMState` int: 2=Running, 3=Off, 9=Paused, 6=Saved, ...) |
| `hyperv.vm.uptime["{#VM.NAME}"]` | `uptime` / `uptime_seconds` |
| `hyperv.vm.cpu.usage["{#VM.NAME}"]` | `cpu_usage_percent` |
| `hyperv.vm.cpu.count["{#VM.NAME}"]` | `cpu_cores` |
| `hyperv.vm.memory["{#VM.NAME}"]` | `memory_allocated_bytes` / `memory_allocated_formatted` |
| `hyperv.vm.memory.demand["{#VM.NAME}"]` | `memory_demand_bytes` / `memory_demand_formatted` |
| `hyperv.vm.mac["{#VM.NAME}"]` | `mac_address` |
| `hyperv.vm.ip["{#VM.NAME}"]` | `ip_address` |
| `hyperv.vm.checkpoint.count["{#VM.NAME}"]` | `checkpoint_count` |
| `hyperv.vm.checkpoint.oldest["{#VM.NAME}"]` | `checkpoint_oldest_age_seconds` |

Legacy Hyper-V performance-counter templates (`\Hyper-V Hypervisor Virtual Processor(VM:...)\...`)
are still supported as a best-effort fallback for hosts that only have the standard template, but
they expose far fewer attributes per VM.
