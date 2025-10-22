<#
.SYNOPSIS
    Watch Windows Event Log in near real time.
.DESCRIPTION
    Modified version of David Segura's Watch-AutopilotOOBEevents.ps1 script.
    Original Source: https://github.com/OSDeploy/AutopilotOOBE
.EXAMPLE
    .\Watch-EventLog.ps1

    Run the Watcher and choose Logs interactively.
.EXAMPLE
    . .\Watch-EventLog.ps1
    Watch-EventLog -LogSelection HyperV

    Run the Watcher and show Hyper-V related Event Logs.
.EXAMPLE
    . .\Watch-EventLog.ps1
    Watch-EventLog -LogSelection HyperV -PollIntervalSeconds 2 -CMTrace

    Run the Watcher and show Hyper-V related Event Logs and view the logs in real time using CMTrace. Refresh every two seconds.
    Note that cmtrace.exe must be present in $env:PATH
#>

function Watch-EventLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Application', 'System', 'Security', 'Autopilot', 'Intune', 'HyperV', 'Administrative')]
        [string]$LogSelection,
        [int]$PollIntervalSeconds = 10,
        [switch]$CMTrace,
        [switch]$HideInformationEvents,
        [switch]$Full,
        [DateTime]$StartTime = (Get-Date).AddDays(-1),
        [bool]$Monitor = $true,
        [string]$Title = "EventLogWatcher",
        [string]$CMTraceDownloadUrl = "https://raw.githubusercontent.com/everydayintech/Scripts/main/bin/cmtrace.exe"
    )

    # TODO: Add parameter for .evtx file
    # TODO: Add parameter to ingest all .evtx in a folder
    
    #================================================
    # Main Variables
    #================================================
    $FormatEnumerationLimit = -1

    $LogLevel = @{
        Critical    = 1
        Error       = 2
        Warning     = 3
        Information = 4
    }

    $ExcludeEventId = @()
    if ($LogSelection -eq 'Autopilot' -and (-NOT $Full)) {
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

    $Results = @()

    #================================================
    # Main
    #================================================
    function Start-Main {
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
        $Hostname = $(HOSTNAME.EXE)
        $Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$Title-$Hostname-$LogSelection.log"
        $EnvTemp = (Get-Item -Path $env:TEMP).FullName
        $TranscriptFile = Join-Path $EnvTemp $Transcript
        Start-Transcript -Path $TranscriptFile -ErrorAction Ignore
        $WindowTitle = "$Title [$LogSelection] $TranscriptFile"
        UpdateWindowTitle -WindowTitle $WindowTitle

        $CMTraceLog = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$Title-$Hostname-$LogSelection.cmtrace.log"
        $CMTraceLogFile = Join-Path $EnvTemp $CMTraceLog
        
        # Remove Line Wrap
        reg add HKCU\Console /v LineWrap /t REG_DWORD /d 0 /f

        #================================================
        # FilterHashtable
        #================================================
        $FilterHashtable = @{
            StartTime = $StartTime
            LogName   = (GetLogNameList -LogSelection $LogSelection)
        }

        if ($HideInformationEvents) {
            $FilterHashtable.SuppressHashFilter = @{ Level = $LogLevel.Information }
        }
        #================================================
        # Get-WinEvent Results
        #================================================
        $NewStartTime = Get-Date
        $Results = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Ignore `
        | Sort-Object TimeCreated `
        | Where-Object { $_.Id -notin $ExcludeEventId } 
        $FilterHashtable.StartTime = $NewStartTime

        $Clixml = Join-Path $EnvTemp "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Events.clixml"
        
        $Results | Export-Clixml -Path $Clixml
        Add-Content -Path $CMTraceLogFile -Value (GetCMTraceLog -Results $Results) -Encoding UTF8
        
        if ($CMTrace) {
            if ((Get-Command 'cmtrace.exe' -ErrorAction SilentlyContinue)) {
                Write-Host "using existing cmtrace.exe found in PATH"
            }
            else {
                Write-Warning "cmtrace.exe not found. downloading CMTrace to TEMP directory and adding to PATH..."
                Save-CMTraceExe -CMTraceURL $CMTraceDownloadUrl
            }
            
            & cmtrace.exe "$CMTraceLogFile"
        }

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
                $NewStartTime = Get-Date
                
                $NewResults = @()
                $NewResults = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Ignore `
                | Sort-Object TimeCreated `
                | Where-Object { $_.Id -notin $ExcludeEventId } `
                | Where-Object { $_.TimeCreated -notin $Results.TimeCreated }

                $FilterHashtable.StartTime = $NewStartTime

                if ($NewResults) {
                    [array]$Results += [array]$NewResults
                    [array]$Results | Export-Clixml -Path $Clixml
                    Add-Content -Path $CMTraceLogFile -Value (GetCMTraceLog -Results $NewResults) -Encoding UTF8
                    DisplayResults -Results $NewResults
                }
            }
        }
    }

    #================================================
    # Functions
    #================================================
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

    function DisplayResults {
        param (
            $Results
        )

        $InfoWhite = @()
        $InfoCyan = @(62402, 62406)
        $InfoBlue = @()
        $InfoDarkBlue = @()

        foreach ($Item in $Results) {
            $ShortMessage = ($Item.Message -Split '\n')[0]

            if ($Item.LevelDisplayName -eq 'Error') {
                Write-Host "$($Item.TimeCreated) ERROR:$($Item.Id)`t$($ShortMessage)" -ForegroundColor Red
            }
            elseif ($Item.LevelDisplayName -eq 'Warning') {
                Write-Host "$($Item.TimeCreated) WARN :$($Item.Id)`t$($ShortMessage)" -ForegroundColor Yellow
            }
            elseif (($Item.Message -match 'fail') -or ($Item.Message -match 'empty profile')) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($ShortMessage)" -ForegroundColor Red
            }
            elseif ($Item.Message -like "Autopilot*") {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($ShortMessage)" -ForegroundColor Cyan
            }
            elseif ($Item.Id -in $InfoWhite) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($ShortMessage)" -ForegroundColor White
            }
            elseif ($Item.Id -in $InfoCyan) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($ShortMessage)" -ForegroundColor Cyan
            }
            elseif ($Item.Id -in $InfoBlue) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($ShortMessage)" -ForegroundColor Blue
            }
            elseif ($Item.Id -in $InfoDarkBlue) {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($ShortMessage)" -ForegroundColor DarkBlue
            }
            else {
                Write-Host "$($Item.TimeCreated) INFO :$($Item.Id)`t$($ShortMessage)" -ForegroundColor DarkGray
            }
        }
    }

    function GetCMTraceLog {
        Param(
            $Results
        )

        $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        function GetLine {
            param (
                $Message,
                $Component,
                $TimeCreated,
                [Parameter(Mandatory = $true)]
                [ValidateSet("Info", "Warning", "Error")]
                $Type,
                $Thread
            )
            
            switch ($Type) {
                "Info" { [int]$Type = 1 }
                "Warning" { [int]$Type = 2 }
                "Error" { [int]$Type = 3 }
            }

            # Add whitespace before every newline to improve CMTrace compact text view in list
            if ($Message -is [string]) {
                $Message = $Message.Replace("`n", " `n")
            }

            return "<![LOG[$Message]LOG]!>" + `
                "<time=`"$($TimeCreated.ToString("HH:mm:ss.ffffff"))`" " + `
                "date=`"$($TimeCreated.ToString("M-d-yyyy"))`" " + `
                "component=`"$Component`" " + `
                "context=`"$($context)`" " + `
                "type=`"$Type`" " + `
                "thread=`"$($Thread)`" " + `
                "file=`"`">"
        }
        
        foreach ($Item in $Results) {
            if ($Item.Level -eq $LogLevel.Error) {
                Write-Output (GetLine -TimeCreated $Item.TimeCreated -Message "ERROR: $($Item.Message)" -Type "Error" -Component $Item.ProviderName -Thread $Item.Id) 
            }
            elseif ($Item.Level -eq $LogLevel.Warning) {
                Write-Output (GetLine -TimeCreated $Item.TimeCreated -Message "WARN: $($Item.Message)" -Type "Warning" -Component $Item.ProviderName -Thread $Item.Id) 
            }
            else {
                Write-Output (GetLine -TimeCreated $Item.TimeCreated -Message "INFO: $($Item.Message)" -Type "Info" -Component $Item.ProviderName -Thread $Item.Id) 
            }
        }
    }
    
    function Save-WebFile {
        [CmdletBinding()]
        [OutputType([System.IO.FileInfo])]
        param
        (
            [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
            [Alias('FileUri')]
            [System.String]
            $SourceUrl,

            [Parameter(ValueFromPipelineByPropertyName)]
            [Alias('FileName')]
            [System.String]
            $DestinationName,

            [Alias('Path')]
            [System.String]
            $DestinationDirectory = (Get-Item $env:TEMP).FullName,

            #Overwrite the file if it exists already
            #The default action is to skip the download
            [System.Management.Automation.SwitchParameter]
            $Overwrite,

            [System.Management.Automation.SwitchParameter]
            $WebClient
        )
        #=================================================
        #	Values
        #=================================================
        Write-Verbose "SourceUrl: $SourceUrl"
        Write-Verbose "DestinationName: $DestinationName"
        Write-Verbose "DestinationDirectory: $DestinationDirectory"
        Write-Verbose "Overwrite: $Overwrite"
        Write-Verbose "WebClient: $WebClient"
        #=================================================
        #	DestinationDirectory
        #=================================================
        if (Test-Path "$DestinationDirectory") {
            Write-Verbose "Directory already exists at $DestinationDirectory"
        }
        else {
            New-Item -Path "$DestinationDirectory" -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        #=================================================
        #	Test File
        #=================================================
        $DestinationNewItem = New-Item -Path (Join-Path $DestinationDirectory "$(Get-Random).txt") -ItemType File

        if (Test-Path $DestinationNewItem.FullName) {
            $DestinationDirectory = $DestinationNewItem | Select-Object -ExpandProperty Directory
            Write-Verbose "Destination Directory is writable at $DestinationDirectory"
            Remove-Item -Path $DestinationNewItem.FullName -Force | Out-Null
        }
        else {
            Write-Warning 'Unable to write to Destination Directory'
            break
        }
        #=================================================
        #	DestinationName
        #=================================================
        if ($PSBoundParameters['DestinationName']) {
        }
        else {
            $DestinationNameUri = $SourceUrl -as [System.Uri] # Convert to Uri so we can ignore any query string
            $DestinationName = $DestinationNameUri.AbsolutePath.Split('/')[-1]
        }
        Write-Verbose "DestinationName: $DestinationName"
        #=================================================
        #	WebFileFullName
        #=================================================
        $DestinationDirectoryItem = (Get-Item $DestinationDirectory -Force).FullName
        $DestinationFullName = Join-Path $DestinationDirectoryItem $DestinationName
        #=================================================
        #	OverWrite
        #=================================================
        if ((-not ($PSBoundParameters['Overwrite'])) -and (Test-Path $DestinationFullName)) {
            Write-Verbose 'DestinationFullName already exists'
            Get-Item $DestinationFullName -Force
        }
        else {
            #=================================================
            #	Download
            #=================================================
            $SourceUrl = [Uri]::EscapeUriString($SourceUrl.Replace('%', '~')).Replace('~', '%') # Substitute and replace '%' to avoid escaping os Azure SAS tokens
            Write-Verbose "Testing file at $SourceUrl"
            #=================================================
            #	Test for WebClient Proxy
            #=================================================
            $UseWebClient = $false
            if ($WebClient -eq $true) {
                $UseWebClient = $true
            }
            elseif (([System.Net.WebRequest]::DefaultWebProxy).Address) {
                $UseWebClient = $true
            }
            elseif (!(Get-Command 'curl.exe' -ErrorAction 'SilentlyContinue')) {
                $UseWebClient = $true
            }

            if ($UseWebClient -eq $true) {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls1
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile($SourceUrl, $DestinationFullName)
                $WebClient.Dispose()
            }
            else {
                Write-Verbose "cURL Source: $SourceUrl"
                Write-Verbose "Destination: $DestinationFullName"

                Write-Verbose 'Requesing HTTP HEAD to get Content-Length and Accept-Ranges header'
                $remote = Invoke-WebRequest -UseBasicParsing -Method Head -Uri $SourceUrl
                $remoteLength = [Int64]($remote.Headers.'Content-Length' | Select-Object -First 1)
                $remoteAcceptsRanges = ($remote.Headers.'Accept-Ranges' | Select-Object -First 1) -eq 'bytes'

                $curlCommandExpression = "& curl.exe --insecure --location --output `"$DestinationFullName`" --url `"$SourceUrl`""
    
                if ($host.name -match 'PowerShell ISE Host') {
                    #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
                    $null = Invoke-Expression ($curlCommandExpression + ' 2>&1')
                }
                else {
                    Invoke-Expression $curlCommandExpression
                }

                #=================================================
                #	Continue interrupted download
                #=================================================
                if (Test-Path $DestinationFullName) {
                    $localExists = $true
                }

                $RetryDelaySeconds = 1
                $MaxRetryCount = 10
                $RetryCount = 0
                while (
                    $localExists `
                        -and ((Get-Item $DestinationFullName).Length -lt $remoteLength) `
                        -and $remoteAcceptsRanges `
                        -and ($RetryCount -lt $MaxRetryCount)
                ) {
                    Write-Verbose "Download is incomplete, remote server accepts ranges, will retry in $RetryDelaySeconds second(s)"
                    Start-Sleep -Seconds $RetryDelaySeconds
                    $RetryDelaySeconds *= 2 # retry with exponential backoff
                    $RetryCount += 1
                    $curlCommandExpression = "& curl.exe --insecure --location --continue-at - --output `"$DestinationFullName`" --url `"$SourceUrl`""
                
                    if ($host.name -match 'PowerShell ISE Host') {
                        #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
                        $null = Invoke-Expression ($curlCommandExpression + ' 2>&1')
                    }
                    else {
                        Invoke-Expression $curlCommandExpression
                    }
                }

                if ($localExists -and ((Get-Item $DestinationFullName).Length -lt $remoteLength)) {
                    Write-Verbose "Download is incomplete after $RetryCount retries."
                    Write-Warning "Could not download $DestinationFullName"
                    $null
                }
            }
            #=================================================
            #	Return
            #=================================================
            if (Test-Path $DestinationFullName) {
                Get-Item $DestinationFullName -Force
            }
            else {
                Write-Warning "Could not download $DestinationFullName"
                $null
            }
            #=================================================
        }
    }

    function Save-CMTraceExe {
        [CmdletBinding()]
        param (
            [Parameter()][string]$CMTraceURL
        )

        $TempDir = (Get-Item $env:TEMP).FullName
        $TargetDir = Join-Path $TempDir 'CMTrace'
        New-Item -ItemType Directory $TargetDir -ErrorAction SilentlyContinue | Out-Null

        Save-WebFile -SourceUrl $CMTraceURL -DestinationDirectory $TargetDir -DestinationName 'CMTrace.exe' -Overwrite
        $env:PATH += ";$TargetDir"
    }

    Start-Main 
}

$isDotSourced = $MyInvocation.InvocationName -in '.', ''
if (-NOT $isDotSourced) {
    Watch-EventLog
}