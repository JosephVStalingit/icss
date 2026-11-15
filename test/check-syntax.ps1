$path = 'd:\icss\Deploy-ICSS-HyperV-FullAuto.ps1'
$content = Get-Content $path -Raw -Encoding UTF8
[IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($true)))
Write-Host "BOM added"

$e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$e)
if ($e.Count -eq 0) {
    Write-Host "SYNTAX_OK"
} else {
    $e | ForEach-Object { Write-Host ("ERR line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) }
}