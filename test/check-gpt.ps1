# Parse the GPT of the converted VHDX to confirm the EFI System Partition exists.
$Vhd = 'C:\VMs\ICSS-Cluster\Images\ubuntu-24.04-base.vhdx'
$fs = [System.IO.File]::Open($Vhd, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
try {
    $fs.Position = 512
    $hdr = New-Object byte[] 92
    [void]$fs.Read($hdr, 0, 92)
    $sig = [System.Text.Encoding]::ASCII.GetString($hdr, 0, 8)
    Write-Host ("GPT signature: '{0}'" -f $sig.Trim([char]0))

    if ($sig.StartsWith("EFI PART")) {
        $partLba = [BitConverter]::ToUInt64($hdr, 72)
        $numParts = [BitConverter]::ToUInt32($hdr, 80)
        $partSize = [BitConverter]::ToUInt32($hdr, 84)
        Write-Host ("Partitions: {0} (entry size {1}, table at LBA {2})" -f $numParts, $partSize, $partLba)

        $fs.Position = [int64]($partLba * 512)
        for ($i = 0; $i -lt [Math]::Min($numParts, 10); $i++) {
            $entry = New-Object byte[] $partSize
            [void]$fs.Read($entry, 0, $partSize)
            $typeGuid = ($entry[0..15] | ForEach-Object { $_.ToString('X2') }) -join ''
            if ($typeGuid -match '^0+$') { continue }
            $first = [BitConverter]::ToUInt64($entry, 32)
            $last  = [BitConverter]::ToUInt64($entry, 40)
            $nameBytes = $entry[56..127]
            $name = ([System.Text.Encoding]::Unicode.GetString($nameBytes) -replace '[^\x20-\x7E]', '').Trim()
            $type = switch -Regex ($typeGuid) {
                "28732AC11FF8D211BA4B00A0C93EC93B" { "EFI System Partition" ; break }
                "C12A7328F81F11D2BA4B00A0C93EC93B" { "BIOS Boot" ; break }
                "0FC63DAF8483" { "Linux Filesystem" ; break }
                "E3C9E3160B5C4DB837519F38A5D82519" { "Microsoft Basic Data" ; break }
                default { "Type $typeGuid" }
            }
            Write-Host ("  Part {0}: {1} '{2}' LBA {3}-{4} ({5} MB)" -f ($i+1), $type, $name, $first, $last, [math]::Round((($last-$first+1)*512)/1MB,0))
        }
    }
} finally {
    $fs.Close()
}