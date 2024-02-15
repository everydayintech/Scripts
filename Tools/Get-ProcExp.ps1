<#
.SYNOPSIS
Downloads and runs procexp.exe
.DESCRIPTION
Downloads procexp.exe to temp directory and executes
.LINK
https://everydayintech.com
#>

#=================================================
#	Functions
#=================================================

<#
.SYNOPSIS
Downloads a file from the internet and returns a Get-Item Object
.DESCRIPTION
Downloads a file from the internet and returns a Get-Item Object
.LINK
https://github.com/OSDeploy/OSD/tree/master/Docs
#>
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
        $DestinationDirectory = (Join-Path $env:TEMP 'OSD'),

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
        Break
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
    if ((-NOT ($PSBoundParameters['Overwrite'])) -and (Test-Path $DestinationFullName)) {
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
        elseif (!(Get-Command 'curl.exe' -ErrorAction SilentlyContinue)) {
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
    
            if ($host.name -match 'ConsoleHost') {
                Invoke-Expression "& curl.exe --insecure --location --output `"$DestinationFullName`" --url `"$SourceUrl`""
            }
            else {
                #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
                $Quiet = Invoke-Expression "& curl.exe --insecure --location --output `"$DestinationFullName`" --url `"$SourceUrl`" 2>&1"
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

function Save-ProcExpExe {
    [CmdletBinding()]
    param (
        [Parameter()][string]$DownloadUrl = 'https://download.sysinternals.com/files/ProcessExplorer.zip'
    )
    
    $tempDir = (Get-Item $env:TEMP).FullName
    $Zip = Save-WebFile -SourceUrl $DownloadUrl -DestinationDirectory $tempDir -DestinationName 'ProcessExplorer.zip' -Overwrite

    $ExtractDir = Join-Path $tempDir 'ProcessExplorer'

    if (-NOT (Test-Path $ExtractDir)) {
        New-Item -Path $ExtractDir -ItemType Directory
    }

    Expand-Archive -Path $Zip.FullName -DestinationPath $ExtractDir -Force

    return (Join-Path $ExtractDir 'procexp64.exe')
}

function Set-ProcExpEulaAccepted {
    reg add 'HKCU\SOFTWARE\Sysinternals\Process Explorer' /v EulaAccepted /t REG_DWORD /d 1 /f | Out-Null
}

#=================================================
#	Main
#=================================================

Set-ProcExpEulaAccepted
$ProcExp = Save-ProcExpExe

& "$ProcExp"