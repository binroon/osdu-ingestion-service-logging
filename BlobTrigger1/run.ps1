# Input bindings are passed in via param block.
param([byte[]] $InputBlob, $TriggerMetadata)

# Write out the blob name and size to the information log.
Write-Host "PowerShell Blob trigger function Processed blob! Name: $($TriggerMetadata.Name) Size: $($InputBlob.Length) bytes"


# Description: This script shows how to post Az.Storage Analytics logs to Azure Log Analytics workspace
#
# Before running this script:
#     - Create or have a storage account, and enable analytics logs
#     - Create Azure Log Analytics workspace
#     - Change the following values:
#           - $ResourceGroup
#           - $StorageAccountName
#           - $CustomerId
#           - $SharedKey
#           - $LogType
#
# What this script does:
#     - Use Storage Powershell to enumerate all log blobs in $logs container in a storage account
#     - Use Storage Powershell to read all log blobs
#     - Convert each log line in the log blob to JSON payload
#     - Use Log Analytics HTTP Data Collector API to post JSON payload to Log Analytics workspace
#
# Note: This script is sample code. No support is provided.
#
# Reference:
#     - Log Analytics Data Collector API: https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
#

#Login-AzAccount

# Resource group name for the storage acccount
# $ResourceGroup = "weisun-bm1-afcluster"

# Storage account name
# $StorageAccountName = "weisunbm1afclusterstg"

# Container name for analytics logs
# $ContainerName = "airflow-logs"

# Replace with your Workspace Id
# Find in: Azure Portal > Log Analytics > {Your workspace} > Advanced Settings > Connected Sources > Windows Servers > WORKSPACE ID
$CustomerId = "e0463af3-3694-4476-bcbc-c55bf0ae23db"  
# osdu-la
# Replace with your Primary Key
# Find in: Azure Portal > Log Analytics > {Your workspace} > Advanced Settings > Connected Sources > Windows Servers > PRIMARY KEY
$SharedKey = "FvKgMl7oy9Skf9sfgU31SgCV1XyWTY2mG+ZKxt052TJX1aBA3tLAABX7Iy9Fyp4x3ja+9YmtaPs+pFr09JHHgQ=="

# Specify the name of the record type that you'll be creating
# After logs are sent to the workspace, you will use "MyStorageLogs1_CL" as stream to query.
$LogType = "airflowtest"

# You can use an optional field to specify the timestamp from the data. 
# If the time field is not specified, Log Analytics assumes the time is the message ingestion time
$TimeStampField = ""

# Sample of two records in json to be sent to Log Analytics workspace
$json = @"
[{  "StringValue": "MyString1",
    "NumberValue": 42,
    "BooleanValue": true,
    "DateValue": "2016-05-12T20:00:00.625Z",
    "GUIDValue": "9909ED01-A74C-4874-8ABF-D2678E3AE23D"
},
{   "StringValue": "MyString2",
    "NumberValue": 43,
    "BooleanValue": false,
    "DateValue": "2016-05-12T20:00:00.625Z",
    "GUIDValue": "8809ED01-A74C-4874-8ABF-D2678E3AE23D"
}]
"@

#
# Create the function to create the authorization signature
#
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
    return $authorization
}


#
# Create the function to create and post the request
#
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization"        = $signature;
        "Log-Type"             = $logType;
        "x-ms-date"            = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

# Submit the data to the API endpoint
#Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType

#
# Convert ; to "%3B" between " in the csv line to prevent wrong values output after split with ;
#
Function ConvertSemicolonToURLEncoding([String] $InputText) {
    $ReturnText = ""
    $chars = $InputText.ToCharArray()
    $StartConvert = $false

    foreach ($c in $chars) {
        if ($c -eq '"') {
            $StartConvert = ! $StartConvert
        }

        if ($StartConvert -eq $true -and $c -eq ';') {
            $ReturnText += "%3B"
        }
        else {
            $ReturnText += $c
        }
    }

    return $ReturnText
}

#
# If a text doesn't start with ", add "" for json value format
# If a text contains "%3B", replace it back to ";"
#
Function FormalizeJsonValue($Text) {
    $Text1 = ""
    if ($Text.IndexOf("`"") -eq 0) { $Text1 = $Text } else { $Text1 = "`"" + $Text + "`"" }

    if ($Text1.IndexOf("%3B") -ge 0) {
        $ReturnText = $Text1.Replace("%3B", ";")
    }
    else {
        $ReturnText = $Text1
    }
    return $ReturnText
}

Function GetTimestampValue($Text) {
    # [2020-08-04 03:16:52,219] {bash_operator.py:136} INFO - Temporary script location: /tmp/airflowtmpxb6ayp63/echo_5prn7q8
    $regx = '\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3}'
    If ($Text -match $regx) {
        return $Matches[0]
    }
    else {
        return $null
    }
}

Function GetTaskValue($Text) {
    # [2020-08-04 03:16:52,219] {bash_operator.py:136} INFO - Temporary script location: /tmp/airflowtmpxb6ayp63/echo_5prn7q8
    $regx = '(\{)(.+:\d+)(\})'
    If ($Text -match $regx) {
        return $Matches[2]
    }
    else {
        return $null
    }    
}

Function GetLevelValue($Text) {
    # [2020-08-04 03:16:52,219] {bash_operator.py:136} INFO - Temporary script location: /tmp/airflowtmpxb6ayp63/echo_5prn7q8
    $regx = '(\}) (\w+) (\-)'
    If ($Text -match $regx) {
        return $Matches[2]
    }
    else {
        return $null
    }
}

Function GetContentValue($Text) {
    # [2020-08-04 03:16:52,219] {bash_operator.py:136} INFO - Temporary script location: /tmp/airflowtmpxb6ayp63/echo_5prn7q8
    $regx = '(\}) (\w+) (\-) (\w+.*)'
    If ($Text -match $regx) {
        return $Matches[4]
    }
    else {
        return $null
    }
}

Function ConvertLogLineToJson([String] $logLine) {
    #Convert semicolon to %3B in the log line to avoid wrong split with ";"
    #$logLineEncoded = ConvertSemicolonToURLEncoding($logLine)

    #$elements = $logLineEncoded.split(';')

    $FormattedElements = New-Object System.Collections.ArrayList

    $TimeStampValue = GetTimestampValue($logLine)
    $TaskValue = GetTaskValue($logLine)
    $LevelValue = GetLevelValue($logLine)
    $ContentValue = GetContentValue($logLine)
    $LogFileName = $TriggerMetadata.Name
    $RunId = $TriggerMetadata.Name # .split('/')[1]
    $DagName = $TriggerMetadata.Name # .split('/')[2]
    $TaskName = $TriggerMetadata.Name # .split('/')[3]

    if ($TimeStampValue -and $TaskValue -and $LevelValue -and $ContentValue -and $LogFileName -and $RunId -and $DagName -and $TaskName) {
        # Validate if the text starts with ", and add it if not
        $TimeStampValue = FormalizeJsonValue($TimeStampValue)
        $TaskValue = FormalizeJsonValue($TaskValue)
        $LevelValue = FormalizeJsonValue($LevelValue)
        $ContentValue = FormalizeJsonValue($ContentValue)
        $LogFileName = FormalizeJsonValue($LogFileName) 
        $RunId = FormalizeJsonValue($RunId)
        $DagName = FormalizeJsonValue($DagName)
        $TaskName = FormalizeJsonValue($TaskName)
        

        # Use "> null" to avoid annoying index print in the console
        $FormattedElements.Add($TimeStampValue)
        $FormattedElements.Add($TaskValue)
        $FormattedElements.Add($LevelValue)
        $FormattedElements.Add($ContentValue)
        $FormattedElements.Add($LogFileName)
        $FormattedElements.Add($RunId)
        $FormattedElements.Add($DagName)
        $FormattedElements.Add($TaskName)
        
    }
    else{
        return $null
    }

    $Columns = 
    (   "timestamp",
        "task",
        "level",
        "content",
        "logfilename",
        "runid",
        "dagname",
        "taskname"
    )

    # Propose json payload
    $logJson = "[{";
    For ($i = 0; $i -lt $Columns.Length; $i++) {
        $logJson += "`"" + $Columns[$i] + "`":" + $FormattedElements[$i]
        if ($i -lt $Columns.Length - 1) {
            $logJson += ","
        }
    }
    $logJson += "}]";

    return $logJson
}

###

$successPost = 0
$failedPost = 0

$log = [System.Text.Encoding]::UTF8.GetString($InputBlob, 0, $InputBlob.Length)
# Set-Content $filename $log -Force >Null

Write-Output("> Posting logs to log analytic worspace")
$lines = $log.Split("`r`n", [StringSplitOptions]::RemoveEmptyEntries)

# Enumerate log lines in each log blob
foreach ($line in $lines) {
    Write-Output("line: {0}" -f $line) 
    $json = ConvertLogLineToJson($line)

    if (!$json) {
        continue
    }
    #Write-Output $json
    Write-Output("JsonPayload: {0}"-f $json)
    $response = Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType

    if ($response -eq "200") {
        $successPost++
    }
    else { 
        $failedPost++
        Write-Output "> Failed to post one log to Log Analytics workspace"
    }
}
Write-Output "> Log lines posted to Log Analytics workspace: success = $successPost, failure = $failedPost"
