$accessToken = $env:MS_ACCESS_TOKEN
if ([string]::IsNullOrEmpty($accessToken)) {
    Write-Host "No Access Token specified"
    Write-Host "Set Environment Variable MS_ACCESS_TOKEN first"
    Write-Host "Example: `$env:MS_ACCESS_TOKEN = Get-ClipBoard"
    return
}

# global variables
$allWindowsDevices = @()
$discoveredAppNameToDeviceIdHT = @{}
$discoveredAppNameToAppIdHT = @{}

$intuneDeviceIdToAadDeviceIdHT = @{}
$aadDeviceIdToObjectIdHT = @{}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$headers = @{
    "authorization" = "Bearer $accessToken"
}

# get all intune windows devices (Query copied from Windows devices blade)
$allWindowsDevices = InvokePagedGetRequest -requestUri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=(Notes eq 'bc3e5c73-e224-4e63-9b2b-0c36784b7e80') and (((deviceType eq 'desktop') or (deviceType eq 'windowsRT') or (deviceType eq 'winEmbedded') or (deviceType eq 'surfaceHub') or (deviceType eq 'windows10x') or (deviceType eq 'windowsPhone') or (deviceType eq 'holoLens')))&`$select=deviceName,managementAgent,ownerType,complianceState,deviceType,osVersion,userPrincipalName,lastSyncDateTime,enrolledDateTime,serialNumber,azureADDeviceId,id,deviceRegistrationState,managementState,deviceActionResults,jailbroken,deviceEnrollmentType&`$orderby=enrolledDateTime asc"

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

# build device id conversion hashtables
$allWindowsDevices | ForEach-Object { $intuneDeviceIdToAadDeviceIdHT[$_.id] = $_.azureADDeviceId }
$allWindowsDevices | ForEach-Object { $aadDeviceIdToObjectIdHT[$_.azureADDeviceId] = GetAadObjectIdFromAadDeviceId -deviceId $_.azureADDeviceId }

function GetDetectedAppsOnDevice {
    param (
        $deviceId
    )

    $requestUri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$deviceId')/detectedApps?`$top=50&`$orderBy=displayName asc"
    $data = InvokePagedGetRequest -requestUri $requestUri
    
    return $data
}

function GetDetectedAppsFromMonitor {
    param (
    )

    # filtering for platform does not seem to work ($filter=platform eq 'windows')
    $requestUri = "https://graph.microsoft.com/beta/deviceManagement/detectedApps?`$orderBy=displayName"
    $data = InvokePagedGetRequest -requestUri $requestUri
    return ($data | Where-Object { $_.platform -eq 'windows' })
}

function InvokePagedGetRequest {
    param (
        $requestUri
    )

    $moreDataAvailable = $true
    $data = while ($moreDataAvailable) {
        $response = Invoke-WebRequest -UseBasicParsing `
            -Uri $requestUri `
            -WebSession $session `
            -Headers $headers

        $parsedResponse = $response.Content | ConvertFrom-Json

        # check if more data needs to be retreived
        $nextLink = $parsedResponse.'@odata.nextLink'
        if ($null -ne $nextLink) {
            $requestUri = $nextLink
        }
        else {
            $moreDataAvailable = $false
        }

        # emit data of current request
        $parsedResponse.value
    }

    return $data
}

function DiscoverDetectedAppsOnDevice {
    param (
        $deviceId
    )

    $detectedApps = GetDetectedAppsOnDevice -deviceId $deviceId

    foreach ($detectedApp in $detectedApps) {
        if ([String]::IsNullOrEmpty($detectedApp.displayName)) {
            continue
        }

        Write-Verbose "processing app $($detectedApp.displayName)"
        $hashTableKey = "$($detectedApp.displayName) [$($detectedApp.version)]"

        if ($null -eq $discoveredAppNameToDeviceIdHT[$hashTableKey]) {
            $discoveredAppNameToDeviceIdHT[$hashTableKey] = New-Object -TypeName System.Collections.Generic.HashSet[string]
        }

        $AlreadyPresent = $discoveredAppNameToDeviceIdHT[$hashTableKey].Add($deviceId)
    }
}

function DiscoverDetectedAppsOnAllDevices {
    param (
    )

    foreach ($item in $allWindowsDevices) {
        Write-Host "processing device $($item.deviceName)"
        DiscoverDetectedAppsOnDevice -deviceId $item.id
    }
}

Write-Host "Run DiscoverDetectedAppsOnAllDevices to build index based on every device"

function DiscoverDetectedAppsFromMonitor {
    param (
    )

    $discoveredApps = GetDetectedAppsFromMonitor
    foreach ($item in $discoveredApps) {
        Write-Verbose "processing app $($item.displayName)"
        $hashTableKey = "$($item.displayName) [$($item.version)]"

        if ($null -eq $discoveredAppNameToAppIdHT[$hashTableKey]) {
            $discoveredAppNameToAppIdHT[$hashTableKey] = New-Object -TypeName System.Collections.Generic.HashSet[string]
        }

        $AlreadyPresent = $discoveredAppNameToAppIdHT[$hashTableKey].Add($item.id)
    }
}
Write-Host "Run DiscoverDetectedAppsFromMonitor to build index based on tenant wide monitor data"

function FindDetectedApp {
    param (
        $expression
    )
    
    $matchingKeys = $discoveredAppNameToDeviceIdHT.Keys | Where-Object { $_ -match $expression }
    Write-Verbose "matching keys: $($matchingKeys | Join-String -Separator ', ')"
   
    return $matchingKeys
}

function FindDevicesWithDetectedApp {
    param (
        $expression
    )
    
    $matchingKeys = FindDetectedApp -expression $expression

    $devices = New-Object -TypeName System.Collections.Generic.HashSet[string]
    foreach ($item in $matchingKeys) {
        $deviceIds = $discoveredAppNameToDeviceIdHT[$item] 
        $deviceIds | ForEach-Object { $null = $devices.Add($_) }
    }

    return $devices
}

function GetDevicesWithAppId {
    param (
        $appId
    )
   
    $requestUri = "https://graph.microsoft.com/beta/deviceManagement/detectedApps('$appId')/managedDevices?`$top=50&`$select=id&`$orderby=deviceName asc"
    $data = InvokePagedGetRequest -requestUri $requestUri
    return ($data | Select-Object -ExpandProperty id)
}

function FindDetectedAppFromMonitor {
    param (
        $expression
    )
    
    $matchingKeys = $discoveredAppNameToAppIdHT.Keys | Where-Object { $_ -match $expression }
    Write-Verbose "matching keys: $($matchingKeys | Join-String -Separator ', ')"
   
    return $matchingKeys
}

function FindDevicesWithDetectedAppFromMonitor {
    param (
        $expression
    )
    
    $matchingKeys = FindDetectedAppFromMonitor -expression $expression

    $appIds = New-Object -TypeName System.Collections.Generic.HashSet[string]
    foreach ($item in $matchingKeys) {
        $Ids = $discoveredAppNameToAppIdHT[$item] 
        $Ids | ForEach-Object { $null = $appIds.Add($_) }
    }

    $deviceIds = New-Object -TypeName System.Collections.Generic.HashSet[string]
    foreach ($item in $appIds) {
        $DevIds = GetDevicesWithAppId -appId $item
        $DevIds | ForEach-Object { $null = $deviceIds.Add($_) }
    }

   return $deviceIds 
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

function SendMultipleBatchRequests {
    param (
        [PSCustomObject[]]$RequestObjects
    )

    $maxBatchSize = 20
    $sendCount = 0
    $totalCount = $RequestObjects.Count

    $responses = while ($sendCount -lt $totalCount) {
        $nextRequestObjects = $RequestObjects | Select-Object -First $maxBatchSize -Skip $sendCount
        $sendCount += $nextRequestObjects.Length
        SendBatchRequest -RequestObjects $nextRequestObjects
    }

    $combinedResponse = @{
        batchResponses = $responses
    }

    return $combinedResponse
}

function NewAddDeviceToGroupRequestObject {
    param (
        $GroupId,
        $DeviceObjectId
    )

    $obj = NewBatchRequestObject `
        -Id "member_$($GroupId)_$($DeviceObjectId)" `
        -Method "POST" `
        -Url "/groups/$GroupId/members/`$ref" `
        -Headers @{"Content-Type" = "application/json" } `
        -Body @{"@odata.id" = "https://graph.microsoft.com/beta/directoryObjects/$DeviceObjectId" }

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
        NewAddDeviceToGroupRequestObject -GroupId $GroupId -DeviceObjectId $aadObjectId
    }

    SendMultipleBatchRequests -RequestObjects $batchRequestObjects
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