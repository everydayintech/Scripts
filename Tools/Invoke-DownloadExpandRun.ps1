<#
.SYNOPSIS
    Downloads, expands and runs something.
.DESCRIPTION
    Downloads WinDirStat to temp directory and executes
.LINK
    https://everydayintech.com

    Create URL Parameter String for this script:

    [string]$DownloadUrl = "https://github.com/windirstat/windirstat/releases/download/release/v2.2.2/WinDirStat.zip"
    [string]$FileName = "WinDirStat.zip"
    [string]$SHA256Hash = "8161876730EB80E56B34331BDA633DB83E44AEC9897713A48713633CD6D672E5"
    [bool]$ExpansionNeeded = $true
    [string]$ExpandDirName = 'WinDirStatPortable'
    [string]$ExecutablePath = 'x64/WinDirStat.exe'

    $paramString = "{0}&{1}&{2}&{3}&{4}&{5}" -f $DownloadUrl, $FileName, $SHA256Hash, $ExpansionNeeded, $ExpandDirName, $ExecutablePath
    $paramString = [System.Web.HttpUtility]::UrlEncode($paramString)
    $paramString = "?" + $paramString + "#"

    #>

param (
    [string]$SavePath = (Get-Item $env:TEMP).FullName
)

#=================================================
#	Functions
#=================================================
function Start-Main {
    $Params = Get-UrlParamUserInput

    if($null -eq $Params){
        Write-Warning "No valid arguments found"
        return
    }

    $ExpandPath = Join-Path $SavePath $Params.ExpandDirName
    Write-Verbose "ExpandPath: $ExpandPath"
    $FullExecutablePath = if ($Params.ExpansionNeeded) {
        Join-Path (Join-Path $SavePath $Params.ExpandDirName) $Params.ExecutablePath
    }
    else {
        Join-Path $SavePath $Params.ExecutablePath
    }
    Write-Verbose "FullExecutablePath: $FullExecutablePath"

    Write-Verbose "Downloading $($Params.DownloadUrl)"
    $DownloadFile = Save-WebFile -SourceUrl $Params.DownloadUrl -DestinationDirectory $SavePath -DestinationName $Params.FileName

    Write-Verbose "Checking SHA256 file hash"
    if (-NOT ((Get-FileHash $DownloadFile.FullName).Hash -eq $Params.SHA256Hash)) {
        Write-Warning "Invalid file hash"
        Write-Warning "File downloaded from $($Params.DownloadUrl) does not match SHA256 $($Params.SHA256Hash)"
        $DownloadFile | Remove-Item -Force
        return
    }
    
    if ($Params.ExpansionNeeded) {
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

function Get-UrlParamUserInput {
    if (($Script:MyCommand) -match '\.ps1\?([\w\d%]+)#\s') {
        $decodedPayload = [System.Web.HttpUtility]::UrlDecode($Matches[1])
        $payloadList = $decodedPayload -split '&'

        return [PSCustomObject]@{
            DownloadUrl     = $payloadList[0]
            FileName        = $payloadList[1]
            SHA256Hash      = $payloadList[2]
            ExpansionNeeded = ($payloadList[3] -eq 'True')
            ExpandDirName   = $payloadList[4]
            ExecutablePath  = $payloadList[5]
        }
    }
    else {
        return $null
    }
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