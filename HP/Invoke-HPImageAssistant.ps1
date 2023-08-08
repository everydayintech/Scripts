#irm hpia.everydayin.tech | iex
function Invoke-HPImageAssistant {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    $HPIAUrl = 'https://ftp.ext.hp.com/pub/caps-softpaq/cmit/HPIA.html'
    $HPIAWeb = Invoke-WebRequest -Uri $HPIAUrl -UseBasicParsing
    $DownloadLink = $HPIAWeb.Links | Where-Object { $_.href -match '(hp-hpia-[\d\.]+.exe)' } | Select-Object -First 1
    $DownloadFile = $Matches[1]
    $DownloadPath = Join-Path $env:TEMP $DownloadFile

    Write-Host 'Downloading: ', $DownloadLink.href

    if (Test-Path $DownloadPath) {
        Remove-Item $DownloadPath -Force
    }

    Invoke-WebRequest -Uri $DownloadLink.href -OutFile $DownloadPath

    if (-NOT (Test-Path 'C:\Service')) {
        $null = New-Item -Path 'C:\Service' -ItemType Directory
    }
    if (-NOT (Test-Path 'C:\Service\Tools')) {
        $null = New-Item -Path 'C:\Service\Tools' -ItemType Directory
    }
    if (-NOT (Test-Path 'C:\Service\Tools\HPIA')) {
        $null = New-Item -Path 'C:\Service\Tools\HPIA' -ItemType Directory
    }

    Write-Host "Executing: [$($DownloadPath) /s /f `"C:\Service\Tools\HPIA`"]"

    & $DownloadPath /s /f "C:\Service\Tools\HPIA"   
}

Invoke-HPImageAssistant