<#
.SYNOPSIS
    Watch Windows Event Log in near real time.
.DESCRIPTION
    Modified version of David Segura's Watch-AutopilotOOBEevents.ps1 script.
    Original Source: https://github.com/OSDeploy/AutopilotOOBE
.EXAMPLE
    .\Watch-EventLog.ps1

    Run the Watcher and choose Logs interactively
.EXAMPLE
    . .\Watch-EventLog.ps1
    Watch-EventLog -LogSelection HyperV

    Run the Watcher and show Hyper-V related Event Logs
#>

function Watch-EventLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Application', 'System', 'Security', 'Autopilot', 'Intune', 'HyperV', 'Administrative')]
        [string]$LogSelection,
        [int]$PollIntervalSeconds = 10,
        [switch]$Full,
        [bool]$Monitor = $true,
        [string]$Title = "EventLogWatcher",
        [DateTime]$StartTime = (Get-Date).AddDays(-1)
    )

    $LogLevel = @{
        Critical = 1
        Error = 2
        Warning = 3
        Information = 4
    }

    function DisplayResults {
        param (
            $Results
        )
        #================================================
        # Display Results
        #================================================
        foreach ($Item in $Results) {
            if ($Item.LevelDisplayName -eq 'Error') {
                Write-Host "$($Item.TimeCreated) ERROR:$($Item.Id)`t$($Item.Message)" -ForegroundColor Red
            }
            elseif ($Item.LevelDisplayName -eq 'Warning') {
                Write-Host "$($Item.TimeCreated) WARN :$($Item.Id)`t$($Item.Message)" -ForegroundColor Yellow
            }
            elseif (($Item.Message -match 'fail') -or ($Item.Message -match 'empty profile')) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor Red
            }
            elseif ($Item.Message -like "Autopilot*") {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor Cyan
            }
            elseif ($Item.Id -in $InfoWhite) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor White
            }
            elseif ($Item.Id -in $InfoCyan) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor Cyan
            }
            elseif ($Item.Id -in $InfoBlue) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor Blue
            }
            elseif ($Item.Id -in $InfoDarkBlue) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor DarkBlue
            }
            else {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($Item.Message)" -ForegroundColor DarkGray
            }
        }
    }

    function Get-MyWinEvent {
        param (
            $LogSelection,
            $StartTime
        )

    }

    function UpdateWindowTitle {
        param (
            $WindowTitle,
            $NextRefreshIn
        )

        if ($NextRefreshIn -is [int]) {
            if ($NextRefreshIn -lt 1) {
                $host.ui.RawUI.WindowTitle = "$WindowTitle - refreshing..."
            }
            else {
                $host.ui.RawUI.WindowTitle = "$WindowTitle - next refresh: $NextRefreshIn"
            }
        }
        else {
            $host.ui.RawUI.WindowTitle = $WindowTitle
        }
    }

    function GetLogNameList {
        param (
            $LogSelection
        )
        
        $LogNames = switch ($LogSelection) {
            'Application' {  
                @(
                    'Application'
                )
            }
            'System' {  
                @(
                    'System'
                )
            }
            'Security' {  
                @(
                    'Security'
                )
            }
            'HyperV' { 
                @(
                    'Microsoft-Windows-Hyper-V*'
                )
            }
            'Autopilot' {
                @(
                    'Microsoft-Windows-AAD/Operational'
                    'Microsoft-Windows-AssignedAccess/Admin'
                    'Microsoft-Windows-AssignedAccess/Operational'
                    'Microsoft-Windows-AssignedAccessBroker/Admin'
                    'Microsoft-Windows-AssignedAccessBroker/Operational'
                    'Microsoft-Windows-Crypto-NCrypt/Operational'
                    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
                    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational'
                    'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot'
                    'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService'
                    'Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin'
                    'Microsoft-Windows-Shell-Core/Operational'
                    'Microsoft-Windows-Time-Service/Operational'
                    'Microsoft-Windows-User Device Registration/Admin'
                )
            }
            'Intune' {
                @(
                    'Microsoft-Windows-AAD/Operational'
                    'Microsoft-Windows-Crypto-NCrypt/Operational'
                    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
                    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational'
                    'Microsoft-Windows-Shell-Core/Operational'
                    'Microsoft-Windows-Time-Service/Operational'
                )
            }
            'Administrative' {
                @(
                    "Application",
                    "Security",
                    "System",
                    "HardwareEvents",
                    "Intel Graphics Software",
                    "Internet Explorer",
                    "Key Management Service",
                    "Microsoft-AppV-Client/Admin",
                    "Microsoft-AppV-Client/Virtual Applications",
                    "Microsoft-Windows-All-User-Install-Agent/Admin",
                    "Microsoft-Windows-AppHost/Admin",
                    "Microsoft-Windows-Application Server-Applications/Admin",
                    "Microsoft-Windows-AppModel-Runtime/Admin",
                    "Microsoft-Windows-AppReadiness/Admin",
                    "Microsoft-Windows-AssignedAccess/Admin",
                    "Microsoft-Windows-AssignedAccessBroker/Admin",
                    "Microsoft-Windows-Storage-ATAPort/Admin",
                    "Microsoft-Windows-BitLocker-DrivePreparationTool/Admin",
                    "Microsoft-Client-Licensing-Platform/Admin",
                    "Microsoft-Windows-Containers-CCG/Admin",
                    "Microsoft-Windows-DataIntegrityScan/Admin",
                    "Microsoft-Windows-DataIntegrityScan/CrashRecovery",
                    "Microsoft-Windows-DSC/Admin",
                    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
                    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Autopilot",
                    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Enrollment",
                    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Sync",
                    "Microsoft-Windows-DeviceSetupManager/Admin",
                    "Microsoft-Windows-Dhcp-Client/Admin",
                    "Microsoft-Windows-Dhcpv6-Client/Admin",
                    "Microsoft-Windows-Diagnosis-Scripted/Admin",
                    "Microsoft-Windows-Storage-Disk/Admin",
                    "Microsoft-Windows-DxgKrnl-Admin",
                    "Microsoft-Windows-EDP-Application-Learning/Admin",
                    "Microsoft-Windows-EDP-Audit-Regular/Admin",
                    "Microsoft-Windows-EDP-Audit-TCB/Admin",
                    "Microsoft-Client-License-Flexible-Platform/Admin",
                    "Microsoft-Windows-GenericRoaming/Admin",
                    "Microsoft-Windows-Guest-Network-Service-Admin",
                    "Microsoft-Windows-Host-Network-Service-Admin",
                    "Microsoft-Windows-HostGuardianClient-Service/Admin",
                    "Microsoft-Windows-HostGuardianService-CA/Admin",
                    "Microsoft-Windows-HostGuardianService-Client/Admin",
                    "Microsoft-Windows-Hyper-V-Compute-Admin",
                    "Microsoft-Windows-Hyper-V-Config-Admin",
                    "Microsoft-Windows-Hyper-V-Guest-Drivers/Admin",
                    "Microsoft-Windows-Hyper-V-Hypervisor-Admin",
                    "Microsoft-Windows-Hyper-V-StorageVSP-Admin",
                    "Microsoft-Windows-Hyper-V-VID-Admin",
                    "Microsoft-Windows-Hyper-V-VMMS-Admin",
                    "Microsoft-Windows-Hyper-V-VMMS-Networking",
                    "Microsoft-Windows-Hyper-V-VMMS-Storage",
                    "Microsoft-Windows-Hyper-V-VMSP-Admin",
                    "Microsoft-Windows-Hyper-V-Worker-Admin",
                    "Microsoft-Windows-Kernel-EventTracing/Admin",
                    "Microsoft-Windows-KeyboardFilter/Admin",
                    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Admin",
                    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot",
                    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Diagnostics",
                    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService",
                    "Microsoft-Windows-MUI/Admin",
                    "Microsoft-Windows-PowerShell/Admin",
                    "Microsoft-Windows-PrintBRM/Admin",
                    "Microsoft-Windows-PrintService/Admin",
                    "Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin",
                    "Microsoft-Windows-Provisioning-Diagnostics-Provider/AutoPilot",
                    "Microsoft-Windows-Provisioning-Diagnostics-Provider/ManagementService",
                    "Microsoft-Windows-PushNotification-Platform/Admin",
                    "Microsoft-Windows-RemoteApp and Desktop Connections/Admin",
                    "Microsoft-Windows-RemoteAssistance/Admin",
                    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin",
                    "Microsoft-Windows-RetailDemo/Admin",
                    "Microsoft-Windows-SecurityMitigationsBroker/Admin",
                    "Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin",
                    "Microsoft-Windows-SMBDirect/Admin",
                    "Microsoft-Windows-SMBWitnessClient/Admin",
                    "Microsoft-Windows-Storage-Tiering/Admin",
                    "Microsoft-Windows-Storage-ClassPnP/Admin",
                    "Microsoft-Windows-Storage-Storport/Admin",
                    "Microsoft-Windows-Sudo/Admin",
                    "Microsoft-Windows-TerminalServices-ClientUSBDevices/Admin",
                    "Microsoft-Windows-TerminalServices-LocalSessionManager/Admin",
                    "Microsoft-Windows-TerminalServices-PnPDevices/Admin",
                    "Microsoft-Windows-TerminalServices-Printers/Admin",
                    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
                    "Microsoft-Windows-TerminalServices-ServerUSBDevices/Admin",
                    "Microsoft-Windows-Troubleshooting-Recommended/Admin",
                    "Microsoft-Windows-User Device Registration/Admin",
                    "Microsoft-Windows-VerifyHardwareSecurity/Admin",
                    "Microsoft-Windows-WindowsBackup/ActionCenter",
                    "Microsoft-Windows-Workplace Join/Admin",
                    "Microsoft-ServerManagementExperience",
                    "OpenSSH/Admin",
                    "Visual Studio",
                    "Windows PowerShell"
                )
            }
        }
        return $LogNames
    }

    function GetXMLFilterFromLogNames {
        param (
            $LogNames,
            $TimeDiffMs
        )

        $xml = @'
<QueryList>
<Query Id="0" Path="Application">
'@

        foreach ($Item in $LogNames) {
            if ($TimeDiffMs -is [int]) {
                # <Select Path="Application">*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) &lt;= 10000]]]</Select>
                $xml += '<Select Path="' + $Item + '">*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) &lt;= ' + $TimeDiffMs + ']]]</Select>'
            }
            else {
                # <Select Path="Application">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
                $xml += '<Select Path="' + $Item + '">*[System[(Level=1 or Level=2 or Level=3)]]</Select>'
            }
        }

        $xml += @'
</Query>
</QueryList>
'@

        return $xml
    }

    #================================================
    # Initialize
    #================================================
    UpdateWindowTitle -WindowTitle $Title
    $host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.size(2000, 2000)
    $host.ui.RawUI.BackgroundColor = ($bckgrnd = 'Black')
    Clear-Host
    #================================================
    # Transcript
    #================================================
    $Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$Title.log"
    $EnvTemp = (Get-Item -Path $env:TEMP).FullName
    $TranscriptFile = Join-Path $EnvTemp $Transcript
    Start-Transcript -Path $TranscriptFile -ErrorAction Ignore
    $WindowTitle = "$Title $TranscriptFile"
    UpdateWindowTitle -WindowTitle $WindowTitle
    #================================================
    # Main Variables
    #================================================
    $Results = @()
    $FormatEnumerationLimit = -1
    
    $InfoWhite = @()
    $InfoCyan = @(62402, 62406)
    $InfoBlue = @()
    $InfoDarkBlue = @()
    
    if ($Full) {
        $ExcludeEventId = @()
    }
    else {
        $ExcludeEventId = @(3, 9, 10, 11, 90, 91)
        $ExcludeEventId += @(101, 104, 106, 108, 110, 111, 112, 144)
        $ExcludeEventId += @(200, 202, 257, 258, 259, 260, 263, 265, 266, 272)
        $ExcludeEventId += @(507, 509, 510, 511, 512, 513, 514, 516, 518, 520, 522, 524, 525)
        $ExcludeEventId += @(813)
        $ExcludeEventId += @(1000, 1001, 1100, 1101, 1102, 1709)
        $ExcludeEventId += @(28017, 28018, 28019, 28032, 28115, 28125)
        $ExcludeEventId += @(62144, 62170, 62460)
        $ExcludeEventId += @(705, 1007)
    }

    # Remove Line Wrap
    reg add HKCU\Console /v LineWrap /t REG_DWORD /d 0 /f

    #================================================
    # FilterHashtable
    #================================================
    $FilterHashtable = @{
        StartTime = $StartTime
        LogName   = (GetLogNameList -LogSelection $LogSelection)
        Level     = @($LogLevel.Critical, $LogLevel.Error, $LogLevel.Warning, $LogLevel.Information)
    }
    #================================================
    # Get-WinEvent Results
    #================================================
    $Results = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Ignore | Sort-Object TimeCreated | Where-Object { $_.Id -notin $ExcludeEventId }
    $Results = $Results | Select-Object TimeCreated, LevelDisplayName, LogName, Id, @{Name = 'Message'; Expression = { ($_.Message -Split '\n')[0] } }
    $Clixml = "$EnvTemp\$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Events.clixml"
    $Results | Export-Clixml -Path $Clixml
    DisplayResults -Results $Results
    #================================================
    # Monitor New Events
    #================================================
    if ($Monitor) {
        Write-Host -ForegroundColor Cyan "Listening for new events"
        while ($true) {
            $SecondsPassedWaiting = 0
            while ($SecondsPassedWaiting -le $PollIntervalSeconds) {
                UpdateWindowTitle -WindowTitle $WindowTitle -NextRefreshIn ($PollIntervalSeconds - $SecondsPassedWaiting)
                Start-Sleep -Seconds 1
                $SecondsPassedWaiting += 1
            }
            #================================================
            # Get-WinEvent NewResults
            #================================================
            $NewResults = @()
            $NewResults = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Ignore | Sort-Object TimeCreated | Where-Object { $_.Id -notin $ExcludeEventId } | Where-Object { $_.TimeCreated -notin $Results.TimeCreated }
            if ($NewResults) {
                [array]$Results += [array]$NewResults
                [array]$Results | Export-Clixml -Path $Clixml
            }
            $NewResults = $NewResults | Select-Object TimeCreated, LevelDisplayName, LogName, Id, @{Name = 'Message'; Expression = { ($_.Message -Split '\n')[0] } }
            DisplayResults -Results $NewResults
        }
    }
}

$isDotSourced = $MyInvocation.InvocationName -in '.', ''
if (-NOT $isDotSourced) {
    Watch-EventLog
}