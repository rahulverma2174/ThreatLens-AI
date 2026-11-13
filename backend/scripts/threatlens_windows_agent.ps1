param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,
    [string]$CheckpointPath = "$env:LOCALAPPDATA\ThreatLens\windows-security-cursor.json",
    [ValidateRange(1, 300)]
    [int]$PollSeconds = 15,
    [ValidateRange(100, 10000)]
    [int]$RecordIdSpan = 1000,
    [ValidateRange(1, 100)]
    [int]$BatchSize = 100
)

$ErrorActionPreference = "Stop"
$stateDirectory = Join-Path $env:LOCALAPPDATA "ThreatLens"
if (-not (Test-Path -LiteralPath $stateDirectory)) {
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
}
$tokenPath = Join-Path $stateDirectory "source-token.dpapi"
$token = $env:THREATLENS_SOURCE_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
    if (Test-Path -LiteralPath $tokenPath) {
        $secureToken = Get-Content -LiteralPath $tokenPath -Raw | ConvertTo-SecureString
    } else {
        $secureToken = Read-Host "Paste the one-time ThreatLens source token" -AsSecureString
        $secureToken | ConvertFrom-SecureString | Set-Content -LiteralPath $tokenPath -Encoding ASCII
    }
    $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try {
        $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
    }
}

$endpoint = $ApiBaseUrl.TrimEnd("/") + "/api/ingestion/windows/events"
$heartbeatEndpoint = $ApiBaseUrl.TrimEnd("/") + "/api/ingestion/windows/heartbeat"

function Save-Cursor([long]$RecordId) {
    $directory = Split-Path -Parent $CheckpointPath
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $temporary = "$CheckpointPath.tmp"
    @{ record_id = $RecordId; updated_at = [DateTime]::UtcNow.ToString("o") } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $CheckpointPath -Force
}

function Get-Cursor {
    if (Test-Path -LiteralPath $CheckpointPath) {
        $saved = Get-Content -LiteralPath $CheckpointPath -Raw | ConvertFrom-Json
        return [long]$saved.record_id
    }

    # Start at the current end of the Security log to avoid silently backfilling
    # a machine's entire historical log on first install.
    $latest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
    $recordId = if ($latest) { [long]$latest.RecordId } else { 0L }
    Save-Cursor $recordId
    return $recordId
}

function Convert-WindowsEvent($Event) {
    $xml = [xml]$Event.ToXml()
    $fields = @{}
    foreach ($field in $xml.Event.EventData.Data) {
        $name = $field.GetAttribute("Name")
        if ([string]::IsNullOrWhiteSpace($name)) { $name = "Data" }
        $fields[$name] = [string]$field.InnerText
    }
    return @{
        event_id = [int]$Event.Id
        record_id = [long]$Event.RecordId
        computer = [string]$Event.MachineName
        channel = "Security"
        time_created = $Event.TimeCreated.ToUniversalTime().ToString("o")
        event_data = $fields
    }
}

function Send-RecordRange([long]$FromRecordId, [long]$ToRecordId) {
    $xpath = "*[System[(EventID=4624 or EventID=4625) and (EventRecordID > $FromRecordId) and (EventRecordID <= $ToRecordId)]]"
    $records = @(Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction SilentlyContinue | Sort-Object RecordId)
    if ($records.Count -eq 0) { return }

    for ($start = 0; $start -lt $records.Count; $start += $BatchSize) {
        $end = [Math]::Min($start + $BatchSize - 1, $records.Count - 1)
        $batch = @($records[$start..$end] | ForEach-Object { Convert-WindowsEvent $_ })
        $body = @{ events = $batch } | ConvertTo-Json -Depth 8 -Compress
        Invoke-RestMethod -Uri $endpoint -Method Post -Headers @{ Authorization = "Bearer $token" } `
            -ContentType "application/json" -Body $body -TimeoutSec 30 | Out-Null
    }
}

Write-Host "ThreatLens Windows Security collector started. API: $endpoint"
Write-Host "Collecting Security events 4624/4625. Stop with Ctrl+C."

$cursor = Get-Cursor
while ($true) {
    try {
        Invoke-RestMethod -Uri $heartbeatEndpoint -Method Post -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 15 | Out-Null
    } catch {
        Write-Warning "Windows collector heartbeat was not acknowledged. $($_.Exception.Message)"
    }
    try {
        $latestEvent = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($latestEvent) {
            $latestRecordId = [long]$latestEvent.RecordId
            if ($latestRecordId -lt $cursor) {
                # The Security log was cleared or recreated. Re-read the current
                # retained log; the server deduplicates previously accepted rows.
                Write-Warning "Security log record ID moved backwards; replaying the retained log."
                $cursor = 0
                Save-Cursor $cursor
            }
            while ($cursor -lt $latestRecordId) {
                $upper = [Math]::Min($cursor + $RecordIdSpan, $latestRecordId)
                Send-RecordRange $cursor $upper
                $cursor = $upper
                Save-Cursor $cursor
            }
        }
    } catch {
        Write-Warning "Windows event batch was not acknowledged; cursor is unchanged for that range. $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $PollSeconds
}
