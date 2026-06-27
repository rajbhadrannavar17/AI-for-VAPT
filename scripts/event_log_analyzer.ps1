param(
  [string]$LogName = "Security",
  [int]$Hours = 24
)

$start = (Get-Date).AddHours(-1 * $Hours)
$ids = @(4625, 4624, 4672, 4688, 4720, 4726, 4732)

Get-WinEvent -FilterHashtable @{LogName=$LogName; StartTime=$start; Id=$ids} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName, Message |
  ForEach-Object {
    $summary = $_.Message -replace "`r|`n", " "
    [PSCustomObject]@{
      Time = $_.TimeCreated
      EventId = $_.Id
      Provider = $_.ProviderName
      Summary = $summary.Substring(0, [Math]::Min(220, $summary.Length))
    }
  } |
  Format-Table -AutoSize
