import json
from jass.db.database import get_db, Base, engine
from jass.db.models import PropertyCategory, HostProperty, ProberParser, ProberTask
from datetime import datetime

# Common PowerShell preamble with ConvertTo-Json polyfill for PowerShell 2.0
# The polyfill is conditional: only activates when ConvertTo-Json is not available (PS 2.0).
# Uses a recursive pure-PowerShell JSON encoder to avoid JavaScriptSerializer's
# circular reference bugs with PSObject/PSCustomObject.
_PS_POLYFILL = (
    "if (-not (Get-Command ConvertTo-Json -ErrorAction SilentlyContinue)) { "
    "function ConvertTo-Json { "
    "param($InputObject, [int]$Depth=4, [switch]$Compress) "
    "function _enc($obj, $d) { "
    "if ($d -le 0 -or $obj -eq $null) { return 'null' } "
    "if ($obj -is [bool]) { return $obj.ToString().ToLower() } "
    "if ($obj -is [byte] -or $obj -is [int] -or $obj -is [long] -or $obj -is [double] -or $obj -is [decimal]) { return $obj.ToString() } "
    "if ($obj -is [string]) { "
    "$esc = $obj.Replace('\\','\\\\').Replace('\"','\\\"').Replace(\"`r\",'\\r').Replace(\"`n\",'\\n').Replace(\"`t\",'\\t'); "
    "return '\"' + $esc + '\"' } "
    "if ($obj -is [System.Collections.IDictionary]) { "
    "$p = @(); foreach ($k in $obj.Keys) { $p += '\"' + $k + '\":' + (_enc $obj[$k] ($d-1)) }; "
    "return '{' + ($p -join ',') + '}' } "
    "if ($obj -is [System.Collections.IEnumerable]) { "
    "$p = @(); foreach ($i in $obj) { $p += _enc $i ($d-1) }; "
    "return '[' + ($p -join ',') + ']' } "
    "$p = @(); "
    "foreach ($pr in $obj.PSObject.Properties) { "
    "$p += '\"' + $pr.Name + '\":' + (_enc $pr.Value ($d-1)) }; "
    "return '{' + ($p -join ',') + '}' "
    "} "
    "Write-Output (_enc $InputObject $Depth) "
    "} }; "
)

_PS_PREAMBLE = _PS_POLYFILL + "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='SilentlyContinue';"

_PARSER_PREAMBLE = r'''
import json
def _extract_json_fragment(text: str):
    if not text:
        return None
    text = text.strip()
    start_candidates = [i for i in (text.find("{"), text.find("[")) if i != -1]
    if not start_candidates:
        return None
    start = min(start_candidates)
    end = max(text.rfind("}"), text.rfind("]"))
    if end == -1 or end < start:
        return None
    return text[start : end + 1]

def _safe_json_loads(text: str):
    # PowerShell console host sometimes hard-wraps stdout at 80 or 120 columns.
    # We strip literal newlines to counteract this console wrapping.
    text_clean = text.replace('\r', '').replace('\n', '')
    
    # Try decoding as Base64 first to completely bypass OS/Go encoding corruption
    try:
        import base64
        decoded_bytes = base64.b64decode(text_clean, validate=True)
        decoded_str = decoded_bytes.decode('utf-8')
        frag = _extract_json_fragment(decoded_str)
        if frag:
            return json.loads(frag)
    except Exception:
        pass

    # Fallback to plain JSON parsing
    frag = _extract_json_fragment(text_clean)
    if not frag:
        return None
    try:
        return json.loads(frag)
    except Exception:
        return None
'''

PARSERS = {
    "listening_ports": _PARSER_PREAMBLE + '''
def parse(output: str):
    try:
        parsed = _safe_json_loads(output)
        if parsed is None:
            return {"listening_ports": []}
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
    "hardware_inventory": _PARSER_PREAMBLE + '''
def parse(output: str):
    try:
        parsed = _safe_json_loads(output)
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
    "installed_applications": _PARSER_PREAMBLE + '''
def parse(output: str):
    try:
        parsed = _safe_json_loads(output)
        if parsed is None:
            return {"installed_applications": []}
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
    "event_log_errors": _PARSER_PREAMBLE + '''
def parse(output: str):
    try:
        parsed = _safe_json_loads(output)
        if parsed is None:
            return {"event_log_errors": []}
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
    "disk_content_scan": _PARSER_PREAMBLE + '''
def parse(output: str):
    try:
        parsed = _safe_json_loads(output)
        if parsed is None:
            return {"disk_content_scan": []}
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
    "rds_info": _PARSER_PREAMBLE + '''
def parse(output: str):
    try:
        parsed = _safe_json_loads(output)
        if parsed is None:
            return {"rds_info": {}}
        if isinstance(parsed, list):
            res = parsed[0] if parsed else {}
        else:
            res = parsed
        return {"rds_info": res}
    except Exception:
        return {"rds_info": {}}
''',
    "recent_logins": _PARSER_PREAMBLE + '''
def parse(output: str):
    try:
        parsed = _safe_json_loads(output)
        if parsed is None:
            return {"recent_logins": []}
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
            "if ($c) { $res = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue; if ($res) { $res = @($res | Select-Object LocalAddress,LocalPort,OwningProcess,@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}); ConvertTo-Json -InputObject $res -Compress; exit 0 } }; "
            "$ports = netstat -ano -p tcp | Where-Object { $_ -match '(?i)LISTEN|NAS.UCH' }; "
            "$out = @(); "
            "foreach ($p in $ports) { "
            "  $parts = [regex]::Split($p.ToString().Trim(), '\\s+'); "
            "  if ($parts.Count -ge 5 -and $parts[0] -eq 'TCP') { "
            "    $local = $parts[1]; "
            "    $colIdx = $local.LastIndexOf(':'); "
            "    if ($colIdx -gt 0) { "
            "      $addr = $local.Substring(0, $colIdx); "
            "      $port = [int]$local.Substring($colIdx + 1); "
            "      $targetPid = [int]$parts[4]; "
            "      $proc = ''; try { $proc = (Get-Process -Id $targetPid -ErrorAction SilentlyContinue).ProcessName } catch {}; "
            "      $out += New-Object PSObject -Property @{LocalAddress=$addr;LocalPort=$port;OwningProcess=$targetPid;Process=$proc} "
            "    } "
            "  } "
            "}; "
            "if ($out.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $out -Compress }; exit 0"
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
            "$ram = 0; if ($cs -and $cs.TotalPhysicalMemory) { $ram = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) }; "
            "$nics = @(&$getCim Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object Name, MACAddress, Speed); "
            "$disks = @(&$getCim Win32_DiskDrive | Select-Object Model, Size, InterfaceType); "
            "$res = New-Object PSObject -Property @{SerialNumber=$bios.SerialNumber; Manufacturer=$cs.Manufacturer; Model=$cs.Model; CPUs=$cpus; RAM_GB=$ram; NICs=$nics; Disks=$disks; MacAddresses=@($nics | ForEach-Object { $_.MACAddress })}; "
            "ConvertTo-Json -InputObject $res -Depth 4 -Compress; exit 0"
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
            "if ($apps.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $apps -Compress }; exit 0"
        )
    },
    {
        "name": "event_log_errors",
        "description": "Collects Warning/Error entries from System and Application logs from the last 24 hours.",
        "command": (
            _PS_PREAMBLE + " "
            "$events = @(); "
            "$winEvt = Get-Command Get-WinEvent -ErrorAction SilentlyContinue; "
            "if ($winEvt) { "
            "  $events = @(Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 50 -ErrorAction SilentlyContinue | "
            "  Select-Object @{N='TimeCreated';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}},LogName,Id,LevelDisplayName,ProviderName,@{N='Message';E={ if ($_.Message) { $m = $_.Message; foreach($q in 8222,8221,8220,8216,8217,34){ $m = $m.Replace([char]$q, [char]39) }; $m } else { '' } }}) "
            "} else { "
            "  $cutoff = (Get-Date).AddHours(-24); "
            "  foreach ($logName in 'System','Application') { "
            "    $raw = @(Get-EventLog -LogName $logName -EntryType Error,Warning -After $cutoff -Newest 25 -ErrorAction SilentlyContinue); "
            "    foreach ($e in $raw) { "
            "      $msg = ''; if ($e.Message) { $msg = $e.Message }; "
            "      $events += New-Object PSObject -Property @{TimeCreated=$e.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss');LogName=$logName;Id=$e.EventID;LevelDisplayName=$e.EntryType.ToString();ProviderName=$e.Source;Message=$msg} "
            "    } "
            "  } "
            "}; "
            "if ($events.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $events -Compress -Depth 3 }; exit 0"
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
            "Get-ChildItem -Path $d -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object { "
            "$subs = ''; try { $subs = ([System.IO.Directory]::GetDirectories($_.FullName) | ForEach-Object { [System.IO.Path]::GetFileName($_) }) -join ', ' } catch {}; $out += New-Object PSObject -Property @{Drive=$d;Folder=$_.Name;Standard=($known -contains $_.Name);Subfolders=$subs} } }; "
            "if ($out.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $out -Compress }; exit 0"
        )
    },
    {
        "name": "rds_info",
        "description": "Retrieves Remote Desktop Services (RDS) configuration, licenses, installed roles, and active sessions.",
        "command": (
            _PS_PREAMBLE + " "
            "$ts = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue; "
            "$rdp = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue; "
            "$qwinsta = ''; try { $qwinsta = (qwinsta 2>$null | Out-String).Trim() } catch {}; "
            "$enabled = $false; if ($ts -and $ts.fDenyTSConnections -ne $null) { $enabled = ($ts.fDenyTSConnections -eq 0) }; "
            "$port = 3389; if ($rdp -and $rdp.PortNumber -ne $null) { $port = [int]$rdp.PortNumber }; "
            "$res = New-Object PSObject -Property @{TSEnabled=$enabled;Port=$port;Sessions=$qwinsta}; "
            "ConvertTo-Json -InputObject $res -Compress; exit 0"
        )
    },
    {
        "name": "recent_logins",
        "description": "Retrieves counts of interactive logins per user over the last 7 days.",
        "command": (
            _PS_PREAMBLE + " "
            "$matched = @(); "
            "$winEvt = Get-Command Get-WinEvent -ErrorAction SilentlyContinue; "
            "if ($winEvt) { "
            "  $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624;StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue; "
            "  if ($events) { foreach ($e in $events) { $lt = $e.Properties[8].Value; if ($e.Properties.Count -gt 8 -and (2,10 -contains $lt)) { "
            "  $user = $e.Properties[5].Value; if ($user -notmatch 'UMFD|DWM') { $matched += New-Object PSObject -Property @{User=$user} } } } } "
            "} else { "
            "  $events = Get-EventLog -LogName Security -InstanceId 4624 -After (Get-Date).AddDays(-7) -Newest 200 -ErrorAction SilentlyContinue; "
            "  if ($events) { foreach ($e in $events) { "
            "    $msg = $e.Message; $user = ''; "
            "    if ($msg -match 'Logon Type:\\s+(2|10)') { "
            "      if ($msg -match 'Account Name:\\s+(\\S+)') { $user = $matches[1] }; "
            "      if ($user -and $user -notmatch 'UMFD|DWM|\\$') { $matched += New-Object PSObject -Property @{User=$user} } "
            "    } "
            "  } } "
            "}; "
            "if ($matched.Count -gt 0) { $res = @($matched | Group-Object User | Select-Object Name, Count); ConvertTo-Json -InputObject $res -Compress } else { '[]' }; exit 0"
        )
    }
]

def seed_db():
    Base.metadata.create_all(bind=engine)
    
    db = next(get_db())
    try:
        # 1. Categories
        cat_map = {}
        default_categories = [
            {"name": "overview", "display_name": "Overview", "order": 10, "icon": "fa-gauge-high"},
            {"name": "hardware", "display_name": "Hardware", "order": 20, "icon": "fa-microchip"},
            {"name": "apps", "display_name": "Applications", "order": 30, "icon": "fa-cubes"},
            {"name": "network", "display_name": "Network & Ports", "order": 40, "icon": "fa-network-wired"},
            {"name": "logs", "display_name": "Event Logs", "order": 50, "icon": "fa-file-lines"},
        ]
        for cdata in default_categories:
            c = db.query(PropertyCategory).filter_by(name=cdata["name"]).first()
            if not c:
                c = PropertyCategory(**cdata)
                db.add(c)
                db.flush()
            else:
                c.display_name = cdata["display_name"]
                c.order = cdata["order"]
                if not getattr(c, "icon", None) or c.icon == "fa-folder":
                    c.icon = cdata["icon"]
            cat_map[c.name] = c

        # 2. Properties
        default_properties = [
            {"name": "listening_ports", "display_name": "Listening Ports", "data_type": "json", "display_mode": "table", "category": "network"},
            {"name": "serial_number", "display_name": "Serial Number", "data_type": "string", "display_mode": "badge", "category": "hardware"},
            {"name": "manufacturer", "display_name": "Manufacturer", "data_type": "string", "display_mode": "badge", "category": "hardware"},
            {"name": "model", "display_name": "Model", "data_type": "string", "display_mode": "badge", "category": "hardware"},
            {"name": "mac_addresses", "display_name": "MAC Addresses", "data_type": "json", "display_mode": "badge", "category": "hardware"},
            {"name": "cpus", "display_name": "CPUs", "data_type": "json", "display_mode": "table", "category": "hardware"},
            {"name": "ram_gb", "display_name": "RAM (GB)", "data_type": "number", "display_mode": "badge", "category": "hardware"},
            {"name": "nics", "display_name": "Network Interfaces", "data_type": "json", "display_mode": "table", "category": "network"},
            {"name": "disks", "display_name": "Physical Disks", "data_type": "json", "display_mode": "table", "category": "hardware"},
            {"name": "installed_applications", "display_name": "Installed Applications", "data_type": "json", "display_mode": "table", "category": "apps"},
            {"name": "event_log_errors", "display_name": "Event Log Errors", "data_type": "json", "display_mode": "table", "category": "logs"},
            {"name": "disk_content_scan", "display_name": "Disk Folders", "data_type": "json", "display_mode": "table", "category": "hardware"},
            {"name": "rds_info", "display_name": "RDS Info", "data_type": "json", "display_mode": "key_value", "category": "overview"},
            {"name": "recent_logins", "display_name": "Recent Logins", "data_type": "json", "display_mode": "table", "category": "overview"},
        ]
        for pdata in default_properties:
            cat_name = pdata.pop("category")
            cat_id = cat_map[cat_name].id
            p = db.query(HostProperty).filter_by(name=pdata["name"]).first()
            if not p:
                p = HostProperty(**pdata, category_id=cat_id)
                db.add(p)
            else:
                p.display_name = pdata["display_name"]
                p.data_type = pdata["data_type"]
                p.display_mode = pdata["display_mode"]
                p.category_id = cat_id
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

