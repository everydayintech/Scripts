$accessToken = $env:MS_ACCESS_TOKEN
if ([string]::IsNullOrEmpty($accessToken)) {
    Write-Host "No Access Token specified"
    Write-Host "Set Environment Variable MS_ACCESS_TOKEN first"
    Write-Host "Example: `$env:MS_ACCESS_TOKEN = Get-ClipBoard"
    return
}

# global variables
$allWindowsDevices = @()
$allDiscoveredAppsHT = @{}
$intuneDeviceIdToAadDeviceIdHT = @{}
$aadDeviceIdToObjectIdHT = @{}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$headers = @{
    "authorization" = "Bearer $accessToken"
}

# get all intune windows devices
$allWindowsDevicesResponse = Invoke-WebRequest -UseBasicParsing `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=(Notes%20eq%20'bc3e5c73-e224-4e63-9b2b-0c36784b7e80')%20and%20(((deviceType%20eq%20'desktop')%20or%20(deviceType%20eq%20'windowsRT')%20or%20(deviceType%20eq%20'winEmbedded')%20or%20(deviceType%20eq%20'surfaceHub')%20or%20(deviceType%20eq%20'windows10x')%20or%20(deviceType%20eq%20'windowsPhone')%20or%20(deviceType%20eq%20'holoLens')))&`$select=deviceName,managementAgent,ownerType,complianceState,deviceType,osVersion,userPrincipalName,lastSyncDateTime,enrolledDateTime,serialNumber,azureADDeviceId,id,deviceRegistrationState,managementState,exchangeAccessState,exchangeAccessStateReason,deviceActionResults,jailbroken,deviceEnrollmentType&`$orderby=enrolledDateTime%20asc&`$skipToken=Skip='0'&" `
    -WebSession $session `
    -Headers $headers

$allWindowsDevicesResponseJson = $allWindowsDevicesResponse | ConvertFrom-Json
$allWindowsDevices = $allWindowsDevicesResponseJson.value

function GetDevices {
    param (
        $deviceIdList
    )

    if ($null -eq $deviceIdList) {
        return $allWindowsDevices
    }
    else {
        ResolveDevices $deviceIdList
    }
}

# build id conversion hashtables
function GetAadObjectIdFromAadDeviceId {
    param (
        $deviceId
    )

    $getAadDeviceUrl = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '{0}'" -f $deviceId
    $deviceAadInfo = Invoke-RestMethod `
        -Uri $getAadDeviceUrl `
        -Headers $headers -Method Get -ErrorAction Stop

    $objectId = $deviceAadInfo.value | Select-Object -ExpandProperty id
    return $objectId
}

$allWindowsDevices | ForEach-Object { $intuneDeviceIdToAadDeviceIdHT[$_.id] = $_.azureADDeviceId }
$allWindowsDevices | ForEach-Object { $aadDeviceIdToObjectIdHT[$_.azureADDeviceId] = GetAadObjectIdFromAadDeviceId -deviceId $_.azureADDeviceId }

function GetDetectedApps {
    param (
        $deviceId
    )
    
    $detectedAppsResponse = Invoke-WebRequest -UseBasicParsing `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$deviceId')/detectedApps?`$top=1000&`$orderBy=displayName%20asc" `
        -WebSession $session `
        -Headers $headers

    $detectedAppsResponse.Content | ConvertFrom-Json
}

function DiscoverDetectedApps {
    param (
        $deviceId
    )

    $detectedApps = (GetDetectedApps -deviceId $deviceId).value

    foreach ($detectedApp in $detectedApps) {
        if ([String]::IsNullOrEmpty($detectedApp.displayName)) {
            continue
        }

        Write-Host "processing app $($detectedApp.displayName)"

        if ($null -eq $allDiscoveredAppsHT[$detectedApp.displayName]) {
            $allDiscoveredAppsHT[$detectedApp.displayName] = New-Object -TypeName System.Collections.Generic.HashSet[string]
        }

        $AlreadyPresent = $allDiscoveredAppsHT[$detectedApp.displayName].Add($deviceId)
    }
}

foreach ($item in $allWindowsDevices) {
    DiscoverDetectedApps -deviceId $item.id
}

function FindDevicesWithDetectedApp {
    param (
        $expression
    )
    
    $matchingKeys = $allDiscoveredAppsHT.Keys | Where-Object { $_ -match $expression }
    Write-Verbose "matching keys: $($matchingKeys | Join-String -Separator ', ')"

    $devices = New-Object -TypeName System.Collections.Generic.HashSet[string]
    foreach ($item in $matchingKeys) {
        $deviceIds = $allDiscoveredAppsHT[$item] 
        $deviceIds | ForEach-Object { $null = $devices.Add($_) }
    }

    return $devices
}

function ResolveDevices {
    param (
        $deviceIdList
    )

    if ($null -eq $deviceIdList) {
        return
    }

    if ($deviceIdList.getType() -eq [string]) {
        $idList = @($deviceIdList -split "(?:\s)+")
    }
    else {
        $idList = $deviceIdList
    }

    foreach ($item in $idList) {
        $allWindowsDevices | Where-Object { $_.id -eq $item }
    }
}


function NewBatchRequestObject {
    param (
        $Id,
        $Method,
        $Url,
        $Headers,
        $Body
    )

    [PSCustomObject]@{
        id      = $Id
        method  = $Method
        url     = $Url
        headers = $Headers
        body    = $Body
    }
}

function SendBatchRequest {
    param (
        [PSCustomObject[]]$RequestObjects
    )

    $requestBody = @{
        requests = $RequestObjects
    }

    # TODO: only send n Requests per Batch!

    $requestBodyJson = $requestBody | ConvertTo-Json -Depth 100

    $response = Invoke-WebRequest -UseBasicParsing `
        -Uri "https://graph.microsoft.com/beta/`$batch" `
        -Method "POST" `
        -WebSession $session `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $requestBodyJson

    if ($response.StatusCode -eq 200) {
        return $response.Content | ConvertFrom-Json
    }
    return $response
}

function NewAddDeviceToGroupRequestObject {
    param (
        $GroupId,
        $DeviceId
    )

    $obj = NewBatchRequestObject `
        -Id "member_$($GroupId)_$($DeviceId)" `
        -Method "POST" `
        -Url "/groups/$GroupId/members/`$ref" `
        -Headers @{"Content-Type" = "application/json" } `
        -Body @{"@odata.id" = "https://graph.microsoft.com/beta/directoryObjects/$DeviceId" }

    return $obj 
}

function CreateGroup {
    param (
        $GroupName
    )

    $body = @{
        displayName     = $GroupName
        mailEnabled     = $false
        securityEnabled = $true
        mailNickname    = [guid]::NewGuid()
    } | ConvertTo-Json

    $response = Invoke-WebRequest -UseBasicParsing -Uri "https://graph.microsoft.com/beta/groups" `
        -Method "POST" `
        -WebSession $session `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $body

    if ($response.StatusCode -eq 201) {
        return $response.Content | ConvertFrom-Json
    }
    return $response
}

function AddDevicesToGroup {
    param (
        [string]$GroupId,
        [string[]]$DeviceIds
    )
 
    $batchRequestObjects = $DeviceIds | ForEach-Object {
        $aadObjectId = $aadDeviceIdToObjectIdHT[$intuneDeviceIdToAadDeviceIdHT[$_]]
        NewAddDeviceToGroupRequestObject -GroupId $GroupId -DeviceId $aadObjectId
    }
    SendBatchRequest -RequestObjects $batchRequestObjects
}

function CreateGroupAndAddDevices {
    param (
        [string]$GroupName,
        [string[]]$DeviceIds
    )
    
    $result = CreateGroup -GroupName $GroupName
    $groupId = $result.id

    AddDevicesToGroup -GroupId $groupId -DeviceIds $DeviceIds
}