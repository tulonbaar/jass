<#
    .SYNOPSIS
    Script for monitoring Hyper-V servers.

    .DESCRIPTION
    Provides LLD for Virtual Machines on the server and
    can retrieve JSON with found VMs parameters for dependent items.

    Works only with PowerShell 3.0 and above.
    
    .PARAMETER action
    What we want to do - make LLD or get full JSON with metrics.

    .PARAMETER version
    Print verion number and exit.

    .EXAMPLE
    zbx-hyperv.ps1 lld
    {"data":[{"{#VM.NAME}":"vm01","{#VM.VERSION}":"5.0","{#VM.CLUSTERED}":0,"{#VM.HOST}":"hv01","{#VM.GEN}":2,"{#VM.ISREPLICA}":0}

    .EXAMPLE
    zbx-hyperv.ps1 full
    {"vm01":{"IntegrationServicesState":"","MemoryAssigned":0,"IntegrationServicesVersion":"","NumaSockets":1,"Uptime":0,"State":3,
    "NumaNodes":1,"CPUUsage":0,"Status":"Operating normally","ReplicationHealth":0,"ReplicationState":0}, ...}
    
    .NOTES
    Author: Khatsayuk Alexander
    Github: https://github.com/asand3r/
#>

Param (
    [switch]$version = $False,
    [Parameter(Position=0,Mandatory=$False)][string]$action
)

Import-Module "Hyper-V" -RequiredVersion 1.1

# Script version
$VERSION_NUM="0.3.0"
if ($version) {
    Write-Host $VERSION_NUM
    break
}

# Low-Level Discovery function
function Make-LLD() {
    $vms = Get-VM | Select-Object @{Name = "{#VM.NAME}"; e={$_.VMName}},
                                  @{Name = "{#VM.VERSION}"; e={$_.Version}},
                                  @{Name = "{#VM.CLUSTERED}"; e={[int]$_.IsClustered}},
                                  @{Name = "{#VM.HOST}"; e={$_.ComputerName}},
                                  @{Name = "{#VM.GEN}"; e={$_.Generation}},
                                  @{Name = "{#VM.ISREPLICA}"; e={[int]$_.ReplicationMode}},
                                  @{Name = "{#VM.NOTES}"; e={$_.Notes}}
    return ConvertTo-Json @{"data" = [array]$vms} -Compress
}

# JSON for dependent items
function Get-FullJSON() {
    $to_json = @{}
    
    # Because of IntegrationServicesState is string, I've made a dict to map it to int (better for Zabbix):
    # 0 - Up to date
    # 1 - Update required
    # 2 - unknown state
    $integrationSvcState = @{
        "Up to date" = 0;
        "Update required" = 1;
        "" = 2
    }

    # Pre-fetch snapshots for performance
    $checkpoints = @{}
    try {
        Get-VMSnapshot -VMName * -ErrorAction SilentlyContinue | Group-Object -Property VMName | ForEach-Object {
            $checkpoints[$_.Name] = $_.Group
        }
    } catch {}

    # Pre-fetch network adapters (MAC/IP) for performance
    $netAdapters = @{}
    try {
        Get-VMNetworkAdapter -VMName * -ErrorAction SilentlyContinue | Group-Object -Property VMName | ForEach-Object {
            $netAdapters[$_.Name] = $_.Group
        }
    } catch {}

    Get-VM | ForEach-Object {
        $vm_name = $_.VMName
        $cp_count = 0
        $cp_oldest_age = 0
        
        if ($checkpoints.ContainsKey($vm_name)) {
            $cps = $checkpoints[$vm_name]
            $cp_count = @($cps).Count
            if ($cp_count -gt 0) {
                $oldest_cp = $cps | Sort-Object CreationTime | Select-Object -First 1
                $cp_oldest_age = [math]::Round((New-TimeSpan -Start $oldest_cp.CreationTime).TotalSeconds)
            }
        }

        # Use first adapter's MAC/IP (VMs are usually single-NIC)
        $mac = ""
        $ip = ""
        if ($netAdapters.ContainsKey($vm_name)) {
            $adapter = $netAdapters[$vm_name] | Select-Object -First 1
            $mac = $adapter.MacAddress
            $ip = ($adapter.IPAddresses | Select-Object -First 1)
            if (-not $ip) { $ip = "" }
        }

        $vm_data = [psobject]@{"State" = [int]$_.State;
                               "MacAddress" = $mac;
                               "IPAddress" = $ip;
                               "Uptime" = [math]::Round($_.Uptime.TotalSeconds);
                               "NumaNodes" = $_.NumaNodesCount;
                               "NumaSockets" = $_.NumaSocketCount;
                               "ProcessorCount" = $_.ProcessorCount;
                               "IntSvcVer" = [string]$_.IntegrationServicesVersion;
                               "IntSvcState" = $integrationSvcState[$_.IntegrationServicesState];
                               "CPUUsage" = $_.CPUUsage;
                               "Memory" = $_.MemoryAssigned;
                               "MemoryDemand" = $_.MemoryDemand;
                               "ReplMode" = [int]$_.ReplicationMode;
                               "ReplState" = [int]$_.ReplicationState;
                               "ReplHealth" = [int]$_.ReplicationHealth;
                               "StopAction" = [int]$_.AutomaticStopAction;
                               "StartAction" = [int]$_.AutomaticStartAction;
                               "CritErrAction" = [int]$_.AutomaticCriticalErrorAction;
                               "IsClustered" = [int]$_.IsClustered;
                               "CheckpointCount" = $cp_count;
                               "CheckpointOldestAge" = $cp_oldest_age
                               }
        $to_json += @{$vm_name = $vm_data}
    }
    return ConvertTo-Json $to_json -Compress
}

# Main switch
switch ($action) {
    "lld" {
        Write-Host $(Make-LLD)
    }
    "full" {
        Write-Host $(Get-FullJSON)
    }
    Default {Write-Host "Syntax error: Use 'lld' or 'full' as first argument"}
}