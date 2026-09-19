import json
from jass.db.database import get_db, Base, engine
from jass.db.models import PropertyCategory, HostProperty, ProberParser, ProberTask
from datetime import datetime

# Common PowerShell preamble
_PS_PREAMBLE = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='SilentlyContinue';"

PARSERS = {
    "listening_ports": '''
import json
def parse(output: str):
    try:
        parsed = json.loads(output)
        rows = parsed if isinstance(parsed, list) else [parsed]
        res = [
            {
                "address": row.get("LocalAddress"),
                "port": int(row.get("LocalPort")) if str(row.get("LocalPort", "")).isdigit() else row.get("LocalPort"),
                "owning_pid": row.get("OwningProcess"),
                "process": row.get("Process"),
            }
            for row in rows
            if isinstance(row, dict)
        ]
        return {"listening_ports": res}
    except Exception:
        return {"listening_ports": []}
''',
    "hardware_inventory": '''
import json
def parse(output: str):
    try:
        parsed = json.loads(output)
        if not isinstance(parsed, dict):
            return {"hardware_raw": output.strip()}
        macs = parsed.get("MacAddresses") or []
        if isinstance(macs, str):
            macs = [macs]
            
        cpus = parsed.get("CPUs")
        if not isinstance(cpus, list):
            cpus = [cpus] if cpus else []
            
        nics = parsed.get("NICs")
        if not isinstance(nics, list):
            nics = [nics] if nics else []
            
        disks = parsed.get("Disks")
        if not isinstance(disks, list):
            disks = [disks] if disks else []
            
        return {
            "serial_number": parsed.get("SerialNumber"),
            "manufacturer": parsed.get("Manufacturer"),
            "model": parsed.get("Model"),
            "mac_addresses": [m for m in macs if m],
            "cpus": cpus,
            "ram_gb": parsed.get("RAM_GB"),
            "nics": nics,
            "disks": disks
        }
    except Exception:
        return {"hardware_raw": output.strip()}
''',
    "installed_applications": '''
import json
def parse(output: str):
    try:
        parsed = json.loads(output)
        rows = parsed if isinstance(parsed, list) else [parsed]
        res = [
            {
                "name": row.get("DisplayName"),
                "version": row.get("DisplayVersion"),
                "publisher": row.get("Publisher"),
                "install_date": row.get("InstallDate"),
                "install_location": row.get("InstallLocation"),
            }
            for row in rows
            if isinstance(row, dict) and row.get("DisplayName")
        ]
        return {"installed_applications": res}
    except Exception:
        return {"installed_applications": []}
''',
    "event_log_errors": '''
import json
def parse(output: str):
    try:
        parsed = json.loads(output)
        rows = parsed if isinstance(parsed, list) else [parsed]
        res = [
            {
                "time": row.get("TimeCreated"),
                "log_name": row.get("LogName"),
                "event_id": row.get("Id"),
                "level": row.get("LevelDisplayName"),
                "source": row.get("ProviderName"),
                "message": (row.get("Message") or "")[:500],
            }
            for row in rows
            if isinstance(row, dict)
        ]
        return {"event_log_errors": res}
    except Exception:
        return {"event_log_errors": []}
''',
    "disk_content_scan": '''
import json
def parse(output: str):
    try:
        parsed = json.loads(output)
        rows = parsed if isinstance(parsed, list) else [parsed]
        res = [
            {
                "drive": row.get("Drive"),
                "folder": row.get("Folder"),
                "is_standard": bool(row.get("Standard")),
                "subfolders": row.get("Subfolders", ""),
            }
            for row in rows
            if isinstance(row, dict) and row.get("Folder")
        ]
        return {"disk_content_scan": res}
    except Exception:
        return {"disk_content_scan": []}
''',
    "rds_info": '''
import json
def parse(output: str):
    try:
        parsed = json.loads(output)
        if isinstance(parsed, list):
            res = parsed[0] if parsed else {}
        else:
            res = parsed
        return {"rds_info": res}
    except Exception:
        return {"rds_info": {}}
''',
    "recent_logins": '''
import json
def parse(output: str):
    try:
        parsed = json.loads(output)
        rows = parsed if isinstance(parsed, list) else [parsed]
        res = [
            {
                "user": row.get("Name"),
                "count": row.get("Count"),
            }
            for row in rows
            if isinstance(row, dict) and row.get("Name")
        ]
        return {"recent_logins": res}
    except Exception:
        return {"recent_logins": []}
'''
}

PROBES = [
    {
        "name": "listening_ports",
        "description": "Lists TCP ports in LISTEN state and the owning process id.",
        "command": (
            _PS_PREAMBLE + " "
            "$c = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue; "
            "if ($c) { $res = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue; if ($res) { $res | Select-Object LocalAddress,LocalPort,OwningProcess,@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | ConvertTo-Json -Compress; exit } }; "
            "$ports = netstat -ano -p tcp | Where-Object { $_ -match '(?i)LISTEN|NAS' }; "
            "$out = @(); "
            "foreach ($p in $ports) { "
            "  $line = $p.ToString().Trim(); "
            "  $m = [regex]::Match($line, '^\\s*TCP\\s+([0-9.\\[\\]:]+):(\\d+)\\s+.*?\\s+(\\d+)\\s*$'); "
            "  if ($m.Success) { "
            "    $targetPid = [int]$m.Groups[3].Value; "
            "    $port = [int]$m.Groups[2].Value; "
            "    $addr = $m.Groups[1].Value; "
            "    $proc = (Get-Process -Id $targetPid -ErrorAction SilentlyContinue).ProcessName; "
            "    $out += [PSCustomObject]@{LocalAddress=$addr;LocalPort=$port;OwningProcess=$targetPid;Process=$proc} "
            "  } "
            "}; "
            "if ($out.Count -eq 0) { '[]' } else { $out | ConvertTo-Json -Compress }"
        )
    },
    {
        "name": "hardware_inventory",
        "description": "Retrieves BIOS serial, manufacturer/model, CPUs, RAM, connected NICs, and Disks.",
        "command": (
            _PS_PREAMBLE + " "
            "$getCim = { param($cls) if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) { Get-CimInstance $cls -ErrorAction SilentlyContinue } else { Get-WmiObject $cls -ErrorAction SilentlyContinue } }; "
            "$bios = &$getCim Win32_BIOS; "
            "$cs = &$getCim Win32_ComputerSystem; "
            "$cpus = @(&$getCim Win32_Processor | Select-Object -ExpandProperty Name); "
            "$ram = if ($cs -and $cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { 0 }; "
            "$nics = @(&$getCim Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object Name, MACAddress, Speed); "
            "$disks = @(&$getCim Win32_DiskDrive | Select-Object Model, Size, InterfaceType); "
            "[PSCustomObject]@{SerialNumber=$bios.SerialNumber; Manufacturer=$cs.Manufacturer; Model=$cs.Model; CPUs=$cpus; RAM_GB=$ram; NICs=$nics; Disks=$disks; MacAddresses=@($nics | ForEach-Object { $_.MACAddress })} | ConvertTo-Json -Depth 4 -Compress"
        )
    },
    {
        "name": "installed_applications",
        "description": "Enumerates installed applications from the Windows Uninstall registry keys.",
        "command": (
            _PS_PREAMBLE + " "
            "$paths = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; "
            "$apps = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | "
            "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation | Sort-Object DisplayName); "
            "if ($apps.Count -eq 0) { '[]' } else { $apps | ConvertTo-Json -Compress }"
        )
    },
    {
        "name": "event_log_errors",
        "description": "Collects Warning/Error entries from System and Application logs from the last 24 hours.",
        "command": (
            _PS_PREAMBLE + " "
            "$events = @(Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 50 -ErrorAction SilentlyContinue | "
            "Select-Object @{N='TimeCreated';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}},LogName,Id,LevelDisplayName,ProviderName,@{N='Message';E={ if ($_.Message) { $m = $_.Message; foreach($q in 8222,8221,8220,8216,8217,34){ $m = $m.Replace([char]$q, [char]39) }; $m } else { '' } }}); "
            "if ($events.Count -eq 0) { '[]' } else { $events | ConvertTo-Json -Compress -Depth 3 }"
        )
    },
    {
        "name": "disk_content_scan",
        "description": "Lists top-level folders on every fixed drive and flags non-standard (non-OS) folders.",
        "command": (
            _PS_PREAMBLE + " "
            "$known = 'Windows','Program Files','Program Files (x86)','Users','ProgramData','$Recycle.Bin','System Volume Information','PerfLogs'; "
            "$out = @(); "
            "Get-PSDrive -PSProvider FileSystem | ForEach-Object { $d = $_.Root; "
            "Get-ChildItem -Path $d -Directory -ErrorAction SilentlyContinue | ForEach-Object { "
            "$subs = ''; try { $subs = ([System.IO.Directory]::EnumerateDirectories($_.FullName) | ForEach-Object { [System.IO.Path]::GetFileName($_) }) -join ', ' } catch {}; $out += [PSCustomObject]@{Drive=$d;Folder=$_.Name;Standard=($known -contains $_.Name);Subfolders=$subs} } }; "
            "if ($out.Count -eq 0) { '[]' } else { $out | ConvertTo-Json -Compress }"
        )
    },
    {
        "name": "rds_info",
        "description": "Retrieves Remote Desktop Services (RDS) configuration, licenses, installed roles, and active sessions.",
        "command": (
            _PS_PREAMBLE + " "
            "$ts = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue; "
            "$rdp = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue; "
            "$q = qwinsta 2>&1; "
            "$qwinsta = ($q | Out-String).Trim(); "
            "$enabled = if ($ts -and $ts.fDenyTSConnections -ne $null) { $ts.fDenyTSConnections -eq 0 } else { $false }; "
            "$port = if ($rdp -and $rdp.PortNumber -ne $null) { [int]$rdp.PortNumber } else { 3389 }; "
            "[PSCustomObject]@{TSEnabled=$enabled;Port=$port;Sessions=$qwinsta} | ConvertTo-Json -Compress"
        )
    },
    {
        "name": "recent_logins",
        "description": "Retrieves counts of interactive logins per user over the last 7 days.",
        "command": (
            _PS_PREAMBLE + " "
            "$events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624;StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue; "
            "$matched = @(); "
            "if ($events) { foreach ($e in $events) { if ($e.Properties.Count -gt 8 -and ($e.Properties[8].Value -in 2,10)) { "
            "$user = $e.Properties[5].Value; if ($user -notmatch 'UMFD|DWM') { $matched += [PSCustomObject]@{User=$user} } } } }; "
            "if ($matched.Count -gt 0) { $matched | Group-Object User | Select-Object Name, Count | ConvertTo-Json -Compress } else { '[]' }"
        )
    }
]

def seed_db():
    Base.metadata.create_all(bind=engine)
    
    db = next(get_db())
    try:
        # Check if basic categories exist
        if db.query(PropertyCategory).count() == 0:
            # 1. Categories
            overview_cat = PropertyCategory(name="overview", display_name="Overview", order=10)
            hardware_cat = PropertyCategory(name="hardware", display_name="Hardware", order=20)
            apps_cat = PropertyCategory(name="apps", display_name="Applications", order=30)
            network_cat = PropertyCategory(name="network", display_name="Network & Ports", order=40)
            logs_cat = PropertyCategory(name="logs", display_name="Event Logs", order=50)

            db.add_all([overview_cat, hardware_cat, apps_cat, network_cat, logs_cat])
            db.flush()

            # 2. Properties
            props = [
                HostProperty(name="listening_ports", display_name="Listening Ports", data_type="json", category_id=network_cat.id),
                HostProperty(name="serial_number", display_name="Serial Number", data_type="string", category_id=hardware_cat.id),
                HostProperty(name="manufacturer", display_name="Manufacturer", data_type="string", category_id=hardware_cat.id),
                HostProperty(name="model", display_name="Model", data_type="string", category_id=hardware_cat.id),
                HostProperty(name="mac_addresses", display_name="MAC Addresses", data_type="json", category_id=hardware_cat.id),
                HostProperty(name="cpus", display_name="CPUs", data_type="json", category_id=hardware_cat.id),
                HostProperty(name="ram_gb", display_name="RAM (GB)", data_type="number", category_id=hardware_cat.id),
                HostProperty(name="nics", display_name="Network Interfaces", data_type="json", category_id=network_cat.id),
                HostProperty(name="disks", display_name="Physical Disks", data_type="json", category_id=hardware_cat.id),
                HostProperty(name="installed_applications", display_name="Installed Applications", data_type="json", category_id=apps_cat.id),
                HostProperty(name="event_log_errors", display_name="Event Log Errors", data_type="json", category_id=logs_cat.id),
                HostProperty(name="disk_content_scan", display_name="Disk Folders", data_type="json", category_id=hardware_cat.id),
                HostProperty(name="rds_info", display_name="RDS Info", data_type="json", category_id=overview_cat.id),
                HostProperty(name="recent_logins", display_name="Recent Logins", data_type="json", category_id=overview_cat.id),
            ]
            db.add_all(props)
            db.flush()

        # 3. Synchronize Parsers & Tasks (create or update)
        for probe in PROBES:
            name = probe["name"]
            parser_name = f"{name}_parser"
            parser = db.query(ProberParser).filter_by(name=parser_name).first()
            if not parser:
                parser = ProberParser(
                    name=parser_name,
                    description=f"Parser for {name}",
                    code=PARSERS[name]
                )
                db.add(parser)
                db.flush()
            else:
                parser.code = PARSERS[name]
                parser.description = f"Parser for {name}"

            task = db.query(ProberTask).filter_by(name=name).first()
            if not task:
                task = ProberTask(
                    name=name,
                    description=probe["description"],
                    script_type="powershell",
                    content=probe["command"],
                    map_to_properties=True,
                    parser_id=parser.id
                )
                db.add(task)
            else:
                task.content = probe["command"]
                task.description = probe["description"]
                task.parser_id = parser.id
        
        db.commit()
        print("Database seeded and synchronized successfully.")

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_db()

