<#
.SYNOPSIS
    Downloads and runs TeamViewer QS
.DESCRIPTION
    Downloads TeamViewer QS to temp directory and executes
.LINK
    https://everydayintech.com
#>

param (
    [string]$DownloadUrl = "https://download.teamviewer.com/download/TeamViewerQS_x64.exe",
    [string]$FileName = "TeamViewerQS_x64.exe",
    [string]$SavePath = (Get-Item $env:TEMP).FullName,
    [bool]$ExpansionNeeded = $false,
    [string]$ExpandDirName = '',
    [string]$ExecutablePath = 'TeamViewerQS_x64.exe'
)

#=================================================
#	Functions
#=================================================
function Start-Main {
    $ExpandPath = Join-Path $SavePath $ExpandDirName
    Write-Verbose "ExpandPath: $ExpandPath"
    $FullExecutablePath = if ($ExpansionNeeded) {
        Join-Path (Join-Path $SavePath $ExpandDirName) $ExecutablePath
    }
    else {
        Join-Path $SavePath $ExecutablePath
    }
    Write-Verbose "FullExecutablePath: $FullExecutablePath"

    Write-Verbose "Downloading $DownloadUrl"
    $DownloadFile = Save-WebFile -SourceUrl $DownloadUrl -DestinationDirectory $SavePath -DestinationName $FileName
    
    if ($ExpansionNeeded) {
        Write-Verbose "Expansion needed"
        if (-NOT (Test-Path $ExpandPath)) {
            Write-Verbose "Creating directory $ExpandPath"
            New-Item -Path $ExpandPath -ItemType Directory | Out-Null
        }

        Write-Verbose "Expanding Archive $($DownloadFile.FullName)"
        Expand-Archive -Path $DownloadFile.FullName -DestinationPath $ExpandPath -Force
    }

    Write-Verbose "Invoking: $FullExecutablePath"
    & "$FullExecutablePath"
}

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

            Write-Verbose 'Requesing HTTP HEAD to get Content-Length and Accept-Ranges header'
            $remote = Invoke-WebRequest -UseBasicParsing -Method Head -Uri $SourceUrl
            $remoteLength = [Int64]($remote.Headers.'Content-Length' | Select-Object -First 1)
            $remoteAcceptsRanges = ($remote.Headers.'Accept-Ranges' | Select-Object -First 1) -eq 'bytes'

            $curlCommandExpression = "& curl.exe --insecure --location --output `"$DestinationFullName`" --url `"$SourceUrl`""
    
            if ($host.name -match 'PowerShell ISE Host') {
                #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
                $Quiet = Invoke-Expression ($curlCommandExpression + ' 2>&1')
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
                    $Quiet = Invoke-Expression ($curlCommandExpression + ' 2>&1')
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

#=================================================
#	Main
#=================================================
Start-Main