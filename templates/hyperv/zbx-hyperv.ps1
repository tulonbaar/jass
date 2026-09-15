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

# SIG # Begin signature block
# MIIfggYJKoZIhvcNAQcCoIIfczCCH28CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAywlUoWvPIeAfv
# QSkQYPw6A1qI5gOpczb+/KXqIUqqEaCCGY8wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggZRMIIFOaADAgECAhMlAAAACQDCR47ksMaRAAAAAAAJMA0G
# CSqGSIb3DQEBDQUAMFYxFTATBgoJkiaJk/IsZAEZFgVsb2NhbDEbMBkGCgmSJomT
# 8ixkARkWC3pwY290bXVjaG93MSAwHgYDVQQDExd6cGNvdG11Y2hvdy1OWS1DQS0w
# MS1DQTAeFw0yNjA5MTExMTI0MTZaFw0yNzA5MTExMTI0MTZaMGsxFTATBgoJkiaJ
# k/IsZAEZFgVsb2NhbDEbMBkGCgmSJomT8ixkARkWC3pwY290bXVjaG93MQwwCgYD
# VQQLEwNaUEMxDjAMBgNVBAsTBVVzZXJzMRcwFQYDVQQDDA7FgXVrYXN6IEJhcnRv
# czCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANYctACrgl4YSUye/63V
# UJiCHpvboLvNkbA6oJiCiL/01oBUWDvl1QKGCcQOhpMPZBqh1EcarLNFtXdm5yJu
# PZt9GKvj18dUwc9qsAVUUoDkRXXKltNdEVBaUs3+h7IfbwiRyjqglY9D4VlCNvfo
# f+PX3L8q1t6iN5pUezTI3rIbjBepL1OOkN4aOXs642SgGmmPY7wWpbk9oKbk+o7P
# gndn/QCezhe5lwcVB+2C4qqWqXccC2sdwEGWwm58vyaB24MrvK6P4maraR1fm2k5
# zRC8FTYcxYOKJJy8VZnKd7kXJOqjP4qwRJddSaeyIJKZGNLmLgkcBsvk2ZnCeGo7
# oz0CAwEAAaOCAwEwggL9MD0GCSsGAQQBgjcVBwQwMC4GJisGAQQBgjcVCIOCgT+F
# 0ethgf2JG4Lks1qDkfBkZYT7qxOGzKtOAgFkAgEDMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMA4GA1UdDwEB/wQEAwIHgDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMD
# MB0GA1UdDgQWBBROR/p4sudM54Mb1QWg1meTx0wjyTAfBgNVHSMEGDAWgBQoeOak
# Ngiw/O9qUrzGixBPeFdCaDCB3AYDVR0fBIHUMIHRMIHOoIHLoIHIhoHFbGRhcDov
# Ly9DTj16cGNvdG11Y2hvdy1OWS1DQS0wMS1DQSxDTj1OWS1DQS0wMSxDTj1DRFAs
# Q049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmln
# dXJhdGlvbixEQz16cGNvdG11Y2hvdyxEQz1sb2NhbD9jZXJ0aWZpY2F0ZVJldm9j
# YXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQw
# gc8GCCsGAQUFBwEBBIHCMIG/MIG8BggrBgEFBQcwAoaBr2xkYXA6Ly8vQ049enBj
# b3RtdWNob3ctTlktQ0EtMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
# cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9enBjb3RtdWNo
# b3csREM9bG9jYWw/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRp
# ZmljYXRpb25BdXRob3JpdHkwNwYDVR0RBDAwLqAsBgorBgEEAYI3FAIDoB4MHGx1
# a2Fzei5iYXJ0b3NAenBjb3RtdWNob3cucGwwUAYJKwYBBAGCNxkCBEMwQaA/Bgor
# BgEEAYI3GQIBoDEEL1MtMS01LTIxLTE2ODA5MzEzODUtMzE1MTM0NTM4NS0yOTIz
# MzQzMjA5LTM5MTIyMA0GCSqGSIb3DQEBDQUAA4IBAQAfWY720f0WTPTyaIX/aLf0
# WL0WsvxziRXp+LHt7WYeFDEne612rbaFGOnkaPXqQqJ2mzb722LfHXjzFyAK7M6K
# XzwqXFXrSSm2NDMZuZIN5DAyM9MnGugKE3Z6c96Q0Xd8sagh274iNebLr3dZqChh
# phkmUgtcTexDU1jdxNDf7nz1hgzci5wZ9aaoCdT/y/lCyJUlpGWAgWulBsWDSPAx
# H8sVGNhB25yEQTfeygPTeBL7g77aAKDn8B0BARD3dMNASfJSaPIKrGCKMQ5zskKd
# RVpfsW7VjFKueXoMXIyoBRAESsTDpHPv3hZSvc9PNEre4veMOmUOqSs3j3MBUe5R
# MIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBi
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
# RzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NG
# aHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1
# IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77j
# YMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrY
# hXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVC
# iZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL
# 0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A1
# 9WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7
# fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCr
# O2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOm
# xkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPx
# ul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVM
# Y2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ5
# 9Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB
# 9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J
# 05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HC
# n2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8
# xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam
# 4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6T
# l4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovR
# Diyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8
# BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0wggTV
# oAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENB
# MTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hB
# MjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04xjD4fAkOkbnG
# Qi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZdw5uaAhuWevQ
# KhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4yyYQSPqomT92
# osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqMv9AfGZvp8ygY
# ElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d3z9lcSIHkdvG
# PdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ27k3oHKEXBRG
# fRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pBNY4r3uD7hEmk
# /M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmVZeqTVDgsmzHP
# 5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71fHeu1qMLlLNB
# 3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4tMZae9FvqMOt/
# 9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X+eVtczhCgHCV
# QCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUFMlj
# ijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ens
# y04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggr
# BgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEu
# Y3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0B
# AQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDaMiqsaxWyW5cw
# lT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+OReFreFhnTXSG
# 0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R79ZsfRFYe9UiX
# pXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp1w9Z2CyOyI5o
# r/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylcheWkMlj+CoVRl
# FE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ3dw9K2x1xLtu
# 6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6QHnPXrRNeIzk
# AMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc1P/sV+zWxHXK
# H8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDDW15jERFE4Lvj
# nGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbevGH4punIxM1U
# oi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0/YMxggVJMIIF
# RQIBATBtMFYxFTATBgoJkiaJk/IsZAEZFgVsb2NhbDEbMBkGCgmSJomT8ixkARkW
# C3pwY290bXVjaG93MSAwHgYDVQQDExd6cGNvdG11Y2hvdy1OWS1DQS0wMS1DQQIT
# JQAAAAkAwkeO5LDGkQAAAAAACTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBtc8OAo0hH
# AwL3t91MsciLHMS4LN9zfmTqpANG2Zo0VTANBgkqhkiG9w0BAQEFAASCAQC7JYSv
# DBGCKLIJKcuErBrLWsQeF2uHpXKXbmFLrbGfcLQ53T1+6YBvM5enh0t03lGtySJf
# UKwv5UK4rJVApPkDoY4g42mFQriWjzW3ydksKkllQwCJiy5BPdYQ0+aPuWLEHDid
# FlXpi3rGDgMaqh4aZ/IGeOufUDGdZ8I1E66mvh2rutGkDsdzydqHHzOPzc2DqQem
# 0WMp7jJs2mXDpVaqGL3haYV+iDIlT44kgBrdLZALY8Ic7H1axfPi00SqSgNlISSN
# nFgdT7YsyIUJVEarnyuurgGtWOQDXmirdbClrReLGO+htoU3Kgdt+du8U/h5OIVs
# cvNgYX06FydJd+pxoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAy
# MDI1IENBMQIQCE/cM09+RU7bww+P+ZIYNTANBglghkgBZQMEAgEFAKBpMBgGCSqG
# SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDkxMzE0MTMy
# MlowLwYJKoZIhvcNAQkEMSIEIL8ESd/ptYkWBST/dlewSY+jpq270nA/znX+RAC1
# rxpWMA0GCSqGSIb3DQEBAQUABIICACMxBixhUQ7Yea1MoENTtU6PsQzJyrCfWZ2d
# ai6BfzrqogCOczbSzrbD0r/uJ3j3o+KPeUMDatTbTxUSwW0Drj/jfc3koCp/Fp1D
# scjhApy+2h9Jmo/EMvZebB4kzg7E3KA0ulWFqd1odG7b0b4zTRd2AV6OX8SlmJFA
# +gFZp25lSvcxJ41YNmERuZBcEaQ6uOnUvv6LFnitRXmemwgeNm3uXRRyQLbIpya/
# o5aL/thQzFvXmmLYy9MkNn19rcxi//rncgJiN+RHD/WCnVPvEelKzAEyNSxHHwiG
# PggVUUEIYlowjLjkE0A+GldghV1+GlaM/h8B/h2k0ZIv5TOkxQ00XLFVo+ckKrh+
# CA4g47CUaEzIwhKMBPv4mWwusGlg+6T+NIrcQqnX8KtKtxIi6yWU9T2xbJann/ec
# QyWNSXfSN8Vi0EgKTsb00WOagxv9TfgfTlCoRV7OUeAnO/mRJTMArI6i69i7k1bH
# TA8IdUs0Uv3tMN87NEphzRO2XwVsXntYfg8SrmUGBohqmRou8pbPIlp1t6/jQ83Y
# BgkEgEdozDuO+hi65JMkxDB0nGtMbKNcLYiaTaOB3P1WuWe/ASGFjbeUezS6jzuP
# xJzks+PjtTp9YIY5w1t2QBp5RMWaar/47jviGUerhhPNiscbNA33ewq8DMNjg65e
# 5nTTexqO
# SIG # End signature block
