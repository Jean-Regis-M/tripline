param([string]$Json, [string]$OutDir, [string]$Voice = "", [int]$Rate = 0)
Add-Type -AssemblyName System.Speech
$s = New-Object System.Speech.Synthesis.SpeechSynthesizer
if ($Voice) { $s.SelectVoice($Voice) }
$s.Rate = $Rate
New-Item -ItemType Directory -Force $OutDir | Out-Null
foreach ($seg in (Get-Content $Json -Raw -Encoding UTF8 | ConvertFrom-Json)) {
  $s.SetOutputToWaveFile((Join-Path $OutDir "$($seg.id).wav"))
  $s.Speak($seg.text)
  $s.SetOutputToNull()
}
$s.Dispose()
