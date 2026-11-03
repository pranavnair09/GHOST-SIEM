param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)
$ErrorActionPreference = "Continue"
$Config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
$ApiUrl = [string]$Config.api_url
$PollSeconds = [int]$Config.poll_interval_seconds
$BatchSize = [int]$Config.batch_size
$Lookback = [int]$Config.lookback_minutes_on_start
$Timeout = [int]$Config.request_timeout_seconds

Write-Host "=== GHOST-SIEM WINDOWS EVENT FORWARDER ===" -ForegroundColor Red
Write-Host "Destination: $ApiUrl"
Write-Host "Channels: $($Config.channels -join ', ')"
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow

# RecordId watermarks are maintained per channel for this process lifetime.
$Watermarks = @{}
$StartCutoff = (Get-Date).AddMinutes(-$Lookback)
foreach ($Channel in $Config.channels) { $Watermarks[$Channel] = 0 }

function Convert-Level([long]$Level) {
    switch ($Level) {
        1 { "Critical" }
        2 { "Error" }
        3 { "Warning" }
        4 { "Information" }
        5 { "Verbose" }
        default { "Information" }
    }
}

function Send-EventBatch($Items) {
    if ($Items.Count -eq 0) { return }
    $Body = @{ events = @($Items) } | ConvertTo-Json -Depth 7
    try {
        $Response = Invoke-RestMethod -Uri $ApiUrl -Method Post -ContentType "application/json" `
            -Body $Body -TimeoutSec $Timeout
        Write-Host ("[{0}] sent={1} inserted={2}" -f (Get-Date -Format "HH:mm:ss"),
            $Response.received, $Response.inserted) -ForegroundColor Green
    } catch {
        Write-Warning "Ingestion failed: $($_.Exception.Message)"
    }
}

while ($true) {
    foreach ($Channel in $Config.channels) {
        try {
            $Query = @{ LogName = [string]$Channel }
            if ($Watermarks[$Channel] -gt 0) {
                $Records = @(Get-WinEvent -FilterHashtable $Query -MaxEvents 500 -ErrorAction Stop |
                    Where-Object { $_.RecordId -gt $Watermarks[$Channel] } |
                    Sort-Object RecordId)
            } else {
                $Query["StartTime"] = $StartCutoff
                $Records = @(Get-WinEvent -FilterHashtable $Query -MaxEvents 500 -ErrorAction Stop |
                    Sort-Object RecordId)
            }

            $Batch = @()
            foreach ($Record in $Records) {
                if ($Record.RecordId -gt $Watermarks[$Channel]) {
                    $Watermarks[$Channel] = [long]$Record.RecordId
                }
                $Time = $Record.TimeCreated.ToUniversalTime().ToString("o")
                $Computer = if ($Record.MachineName) { $Record.MachineName } else { $env:COMPUTERNAME }
                $Provider = if ($Record.ProviderName) { $Record.ProviderName } else { "Unknown" }
                $Message = ""
                try { $Message = [string]$Record.Message } catch { $Message = "[Message unavailable]" }
                $EventKey = "$Computer|$Channel|$($Record.RecordId)"
                $Batch += [ordered]@{
                    timestamp = $Time
                    computer = $Computer
                    channel = [string]$Channel
                    provider = $Provider
                    event_id = [int]$Record.Id
                    record_id = [long]$Record.RecordId
                    level = (Convert-Level ([long]$Record.Level))
                    message = $Message
                    source = "windows"
                    event_key = $EventKey
                }
                if ($Batch.Count -ge $BatchSize) {
                    Send-EventBatch $Batch
                    $Batch = @()
                }
            }
            if ($Batch.Count -gt 0) { Send-EventBatch $Batch }
        } catch {
            if ($_.Exception.Message -notmatch "No events were found") {
                Write-Warning "Channel '$Channel': $($_.Exception.Message)"
            }
        }
    }
    Start-Sleep -Seconds $PollSeconds
}
