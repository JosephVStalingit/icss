<#
    ICSS Hyper-V 3-Node Cluster FULL AUTO Deploy and Test
    Creates 3 Ubuntu VMs with cloud-init (no manual OS install), builds ICSS,
    forms a closed ring, and runs inject/fetch/erasure tests.

    Run as Administrator:
        powershell -ExecutionPolicy Bypass -File Deploy-ICSS-HyperV-FullAuto.ps1

    Requires: Hyper-V enabled, "Default Switch" present, Internet access, ~15GB free disk.
    Uses OpenSSH (client side) to drive the Ubuntu guests.
#>

param(
    [string]$BasePath     = "C:\VMs\ICSS-Cluster",
    [string]$SwitchName   = "Default Switch",
    [int]$VcpuCount       = 2,
    [int]$MemoryGB        = 4,
    [string]$UbuntuVer    = "24.04",
    [string]$TestFileSize = "100MB",
    [string]$VmUser       = "icss",
    [string]$VmPass       = "icss123",
    [string]$SshKeyPath   = "C:\VMs\ICSS-Cluster\icss_key"
)

$ErrorActionPreference = "Stop"

function Log($m)   { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) -ForegroundColor Cyan }
function LogOk($m) { Write-Host ("[{0}] OK  {1}" -f (Get-Date -Format "HH:mm:ss"), $m) -ForegroundColor Green }
function LogErr($m){ Write-Host ("[{0}] ERR {1}" -f (Get-Date -Format "HH:mm:ss"), $m) -ForegroundColor Red }

# ---- 0. hyper-v access check ----
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Log "Not running with a full admin token, but Hyper-V Administrators group membership is enough."
}
try {
    $probe = Get-VM -ErrorAction Stop | Select-Object -First 1
} catch {
    LogErr ("Cannot talk to the Hyper-V service: {0}" -f $_)
    LogErr "Add your account to the 'Hyper-V Administrators' group, or run this script as Administrator."
    exit 1
}
Log "Hyper-V service accessible."

# ---- 1. hyper-v and switch ----
$vmmsvc = Get-Service vmms -ErrorAction SilentlyContinue
if (-not $vmmsvc) { LogErr "The Hyper-V Virtual Machine Management service (vmms) is not installed."; exit 1 }
if ($vmmsvc.Status -ne "Running") { LogErr ("Hyper-V service vmms is {0}." -f $vmmsvc.Status); exit 1 }
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    LogErr ("Virtual switch '{0}' not found." -f $SwitchName); exit 1
}
Log ("Hyper-V ready. Switch: {0}" -f $SwitchName)

# ---- 2. ssh key ----
if (-not (Test-Path $SshKeyPath)) {
    Log ("Generating SSH key {0} ..." -f $SshKeyPath)
    & ssh-keygen -t ed25519 -f $SshKeyPath -N '""' -q
}
$pubKey = (Get-Content "$SshKeyPath.pub" -Raw).Trim()
if (-not $pubKey) { LogErr "Could not read the public key."; exit 1 }
Log ("SSH key ready for user {0}." -f $VmUser)

# ---- 3. ubuntu cloud image (qcow2 -> vhdx via qemu-img) ----
$imgDir  = Join-Path $BasePath "Images"
$imgName = "ubuntu-{0}-server-cloudimg-amd64.img" -f $UbuntuVer
$imgPath = Join-Path $imgDir $imgName

$codename = switch ($UbuntuVer) {
    "22.04" { "jammy" }
    "24.04" { "noble" }
    default { $UbuntuVer }
}
$baseVhdx = Join-Path $imgDir ("ubuntu-{0}-base.vhdx" -f $UbuntuVer)

if (-not (Test-Path $baseVhdx)) {
    New-Item -ItemType Directory -Force -Path $imgDir | Out-Null

    if (-not (Test-Path $imgPath)) {
        $url = "https://cloud-images.ubuntu.com/releases/{0}/release/{1}" -f $codename, $imgName
        Log ("Downloading {0} cloud image ..." -f $UbuntuVer)
        & curl.exe -L --retry 3 --retry-delay 5 -o $imgPath $url
        if (-not (Test-Path $imgPath)) { LogErr "Cloud image download failed."; exit 1 }
    }

    # Hyper-V cannot mount qcow2. Convert it to VHDX with qemu-img.
    $qemuImg = "C:\msys64\ucrt64\bin\qemu-img.exe"
    if (-not (Test-Path $qemuImg)) {
        $qemuImg = "C:\msys64\mingw64\bin\qemu-img.exe"
    }
    if (-not (Test-Path $qemuImg)) {
        LogErr "qemu-img not found. Install it: pacman -S mingw-w64-ucrt-x86_64-qemu-image-util"
        exit 1
    }
    Log "Converting qcow2 to VHDX (this takes a few minutes) ..."
    & $qemuImg convert -O vhdx -o subformat=fixed $imgPath $baseVhdx
    if (-not (Test-Path $baseVhdx)) { LogErr "qemu-img conversion failed."; exit 1 }

    # Hyper-V refuses differencing disks whose parent is flagged as sparse.
    & fsutil.exe sparse setflag $baseVhdx 0 | Out-Null
}
LogOk ("Base VHDX ready: {0}" -f $baseVhdx)

# ---- 4. build cloud-init ISO ----
function New-CloudInitIso {
    param($VmName, $OutIsoPath)

    $workDir = Join-Path (Join-Path $BasePath $VmName) "cidata"
    if (Test-Path $workDir) { Remove-Item $workDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null

    # The account is locked with a placeholder hash; runcmd sets the real password.
    $passHash = '$6$rounds=4096$icss' + ('x' * 43)

    $userData = @"
#cloud-config
hostname: $VmName
manage_etc_hosts: true
users:
  - name: $VmUser
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: $passHash
    ssh_authorized_keys:
  - $pubKey
package_update: true
packages:
  - build-essential
  - libssl-dev
  - git
  - net-tools
  - iproute2
  - qemu-guest-agent
runcmd:
  - systemctl enable ssh
  - systemctl start ssh
  - systemctl enable qemu-guest-agent
  - systemctl start qemu-guest-agent
  - echo "${VmUser}:${VmPass}" | chpasswd
  - sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config
  - systemctl restart ssh
write_files:
  - path: /etc/hostname
    content: $VmName
    owner: root:root
    permissions: "0644"
"@

    $metaData = @"
instance-id: $VmName
local-hostname: $VmName
network:
  version: 2
  ethernets:
    all:
      match:
        name: "en*"
      dhcp4: true
      dhcp6: false
      optional: false
  renderer: networkd
"@

    [IO.File]::WriteAllText((Join-Path $workDir "user-data"), $userData, (New-Object System.Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $workDir "meta-data"), $metaData, (New-Object System.Text.UTF8Encoding($false)))

    # Build the seed ISO with xorriso (the IMAPI2 COM path is not scriptable here).
    # xorriso is an MSYS2 program, so it needs POSIX-style paths.
    $xorriso = "C:\msys64\usr\bin\xorriso.exe"
    if (-not (Test-Path $xorriso)) {
        LogErr "xorriso not found. Install it: pacman -S xorriso"
        exit 1
    }
    function Convert-ToPosixPath([string]$winPath) {
        $full = (Resolve-Path -LiteralPath $winPath -ErrorAction SilentlyContinue)
        if ($full) { $full = $full.Path } else { $full = $winPath }
        $full = $full -replace '\\', '/'
        if ($full -match '^([A-Za-z]):(.*)$') { return "/$($Matches[1].ToLower())$($Matches[2])" }
        return $full
    }
    $posixUserData = Convert-ToPosixPath (Join-Path $workDir "user-data")
    $posixMetaData = Convert-ToPosixPath (Join-Path $workDir "meta-data")
    & $xorriso -as mkisofs -quiet -volid cidata -joliet -rock -output $OutIsoPath $posixUserData $posixMetaData
    if (-not (Test-Path $OutIsoPath)) { LogErr ("ISO was not created: {0}" -f $OutIsoPath); return }
    LogOk ("cloud-init ISO created for {0} ({1} bytes)" -f $VmName, (Get-Item $OutIsoPath).Length)
}

# ---- 5. ssh helper ----
$sshOpts = @(
    "-i", $SshKeyPath,
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=NUL",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes"
)

function Invoke-Ssh {
    param([string]$TargetIp, [string]$Command, [int]$TimeoutSec = 300)
    $args = @()
    $args += $sshOpts
    $args += "{0}@{1}" -f $VmUser, $TargetIp
    $args += $Command
    $out = & ssh @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("ssh failed on {0}: {1}" -f $TargetIp, ($out -join " ")) }
    return $out
}

function Copy-ToNode {
    param([string]$TargetIp, [string]$LocalPath, [string]$RemotePath)
    $args = @("-i", $SshKeyPath, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-o", "BatchMode=yes")
    $args += $LocalPath
    $args += "{0}@{1}:{2}" -f $VmUser, $TargetIp, $RemotePath
    $out = & scp @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("scp failed to {0}: {1}" -f $TargetIp, ($out -join " ")) }
}

# ---- 4. create or reuse the 3 VMs ----
$vmNames = @("icss-node1", "icss-node2", "icss-node3")
$vmIps   = @()

foreach ($name in $vmNames) {
    $vmPath  = Join-Path $BasePath $name
    $childVhd = Join-Path $vmPath ("{0}.vhdx" -f $name)
    $isoPath = Join-Path $vmPath "cidata.iso"

    if (Get-VM -Name $name -ErrorAction SilentlyContinue) {
        Log ("VM {0} already exists, reusing." -f $name)
        $existing = Get-VM -Name $name
        if ($existing.State -ne "Running") { Start-VM -Name $name | Out-Null }
    } else {
        Log ("Creating VM {0} ..." -f $name)
        New-Item -ItemType Directory -Force -Path $vmPath | Out-Null

        # Differencing disk on top of the base VHDX: fast boot, low disk use
        $childVhd = Join-Path $vmPath ("{0}.vhdx" -f $name)
        New-VHD -Path $childVhd -ParentPath $baseVhdx -Differencing | Out-Null

        # Ubuntu cloud images are UEFI (Gen2).
        New-VM -Name $name `
               -MemoryStartupBytes ($MemoryGB * 1GB) `
               -Generation 2 `
               -VHDPath $childVhd `
               -SwitchName $SwitchName | Out-Null
        Set-VMProcessor -VMName $name -Count $VcpuCount
        foreach ($svc in @("Guest Service Interface", "VSS")) {
            try { Enable-VMIntegrationService -VMName $name -Name $svc -ErrorAction Stop }
            catch { Log ("  integration service '{0}' unavailable: {1}" -f $svc, $_.Exception.Message) }
        }

        # The qemu-img converted bootloader is not Microsoft-signed, so Secure Boot
        # must be turned off or the VM refuses to boot ("启动源未通过安全启动验证").
        try {
            Set-VMFirmware -VMName $name -SecureBootTemplate "MicrosoftUEFICertificateAuthority" -EnableSecureBoot Off -ErrorAction Stop
            Log "  Secure Boot disabled."
        } catch {
            Log ("  could not change Secure Boot: {0}" -f $_.Exception.Message)
        }

        New-CloudInitIso -VmName $name -OutIsoPath $isoPath
        Add-VMDvdDrive -VMName $name -Path $isoPath | Out-Null

        Start-VM -Name $name | Out-Null
        LogOk ("VM {0} created and started." -f $name)
    }
}

# ---- 5. wait for cloud-init and collect IPs ----
Log "Waiting for cloud-init and IP addresses (up to 3 min) ..."
$maxWait = 240
$elapsed = 0
while ($vmIps.Count -lt 3 -and $elapsed -lt $maxWait) {
    $vmIps = @()
    foreach ($name in $vmNames) {
        $ip = (Get-VM -Name $name).NetworkAdapters.IPAddresses |
              Where-Object { $_ -match '^(172|192\.168|10)\.' } |
              Select-Object -First 1
        if ($ip) { $vmIps += $ip }
    }
    if ($vmIps.Count -eq 3) { break }
    Start-Sleep -Seconds 15
    $elapsed += 15
    Write-Host ("." * ($elapsed/15)) -NoNewline -ForegroundColor Gray
}
Write-Host ""

if ($vmIps.Count -lt 3) {
    LogErr ("Timed out waiting for IPs after {0}s. Current: {1}" -f $elapsed, ($vmIps -join ", "))
    Log "Possible issues: cloud-init didn't run, ISO not mounted, DHCP failed, or interface name mismatch."
    Log "Check manually: open VM console in Hyper-V Manager and run 'ip a' and 'journalctl -u cloud-init'"
    exit 1
}
LogOk ("Node IPs: {0}" -f ($vmIps -join ", "))

# ---- 6. wait for SSH ----
Log "Waiting for SSH ..."
foreach ($ip in $vmIps) {
    $up = $false
    for ($i=0; $i -lt 40; $i++) {
        if (Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet) { $up = $true; break }
        Start-Sleep -Seconds 3
    }
    if (-not $up) { LogErr ("{0} : SSH port unreachable." -f $ip); exit 1 }
}
LogOk "SSH reachable on all nodes."

# ---- 7. build ICSS on every node (parallel) ----
$srcFile = Join-Path $PSScriptRoot "icss.c"
$makeFile = Join-Path $PSScriptRoot "Makefile"
if (-not (Test-Path $srcFile)) { LogErr ("Source not found: {0}" -f $srcFile); exit 1 }

Log "Copying sources and building ICSS on 3 nodes (parallel) ..."
$buildJobs = @()
foreach ($ip in $vmIps) {
    $buildJobs += Start-Job -ScriptBlock {
        param($targetIp, $key, $user, $src, $mk)
        $sshArgs = @("-i", $key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL",
                     "-o", "ConnectTimeout=10", "-o", "BatchMode=yes")
        $scpArgs = @("-i", $key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-o", "BatchMode=yes")

        & scp @scpArgs $src ("{0}@{1}:/tmp/icss.c" -f $user, $targetIp) 2>&1 | Out-Null
        & scp @scpArgs $mk  ("{0}@{1}:/tmp/Makefile" -f $user, $targetIp) 2>&1 | Out-Null

        $cmd = "mkdir -p ~/icss && mv /tmp/icss.c /tmp/Makefile ~/icss/ && cd ~/icss && " +
               "sudo apt update -qq && sudo apt install -y -qq build-essential libssl-dev && " +
               "make && echo BUILD_OK"
        & ssh @sshArgs ("{0}@{1}" -f $user, $targetIp) $cmd 2>&1
    } -ArgumentList $ip, $SshKeyPath, $VmUser, $srcFile, $makeFile
}

$buildResults = @()
foreach ($j in $buildJobs) { $buildResults += (Receive-Job $j -Wait) }
$buildJobs | Remove-Job
$buildResults | ForEach-Object { Write-Host $_ }
if (($buildResults -join " ") -notmatch "BUILD_OK") { LogErr "Build failed on at least one node."; exit 1 }
LogOk "ICSS built on all 3 nodes."

# ---- 8. start the 3-node ring ----
$ringId      = 1
$chunkSize   = 1048576
$queueDepth  = 32
$listenPort  = 9001
$nodeBin     = "./icss"

$nodeCmds = @(
    ("{0} node --listen {1} --next {2}:{1} --ring-id {3} --chunk-size {4} --queue-depth {5}" -f $nodeBin, $listenPort, $vmIps[1], $ringId, $chunkSize, $queueDepth),
    ("{0} node --listen {1} --next {2}:{1} --ring-id {3} --chunk-size {4} --queue-depth {5}" -f $nodeBin, $listenPort, $vmIps[2], $ringId, $chunkSize, $queueDepth),
    ("{0} node --listen {1} --next {2}:{1} --ring-id {3} --chunk-size {4} --queue-depth {5}" -f $nodeBin, $listenPort, $vmIps[0], $ringId, $chunkSize, $queueDepth)
)

for ($i=0; $i -lt 3; $i++) {
    $startCmd = "cd ~/icss && nohup {0} > node.log 2>&1 &" -f $nodeCmds[$i]
    Invoke-Ssh -TargetIp $vmIps[$i] -Command $startCmd | Out-Null
}
Start-Sleep -Seconds 12
LogOk "3-node ring started."

# ---- 9. test 1: plain inject and fetch ----
$mb       = [int]($TestFileSize.Replace("MB", ""))
$testFile = "/tmp/icss_test_{0}MB.bin" -f $mb

Log ("Test 1: inject {0}MB on node1, fetch from node2 ..." -f $mb)
$hashOut = Invoke-Ssh -TargetIp $vmIps[0] -Command ("cd ~/icss && dd if=/dev/urandom of={0} bs=1M count={1} && ./icss hash {0}" -f $testFile, $mb)
$hash = ($hashOut | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -First 1)
if (-not $hash) { LogErr "Could not compute the test file hash."; exit 1 }
Log ("Test file hash: {0}" -f $hash)

Invoke-Ssh -TargetIp $vmIps[0] -Command ("cd ~/icss && ./icss inject {0} {1}:{2} --ring-id {3} --chunk-size {4}" -f $testFile, $vmIps[0], $listenPort, $ringId, $chunkSize) | ForEach-Object { Write-Host $_ }
Start-Sleep -Seconds 20

Invoke-Ssh -TargetIp $vmIps[1] -Command ("cd ~/icss && ./icss fetch {0} /tmp/icss_restored.bin {1}:{2} --ring-id {3}" -f $hash, $vmIps[1], $listenPort, $ringId) | ForEach-Object { Write-Host $_ }

$verifyOut = Invoke-Ssh -TargetIp $vmIps[1] -Command "cd ~/icss && ./icss hash /tmp/icss_restored.bin"
$verify = ($verifyOut | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -First 1)

if ($hash -eq $verify) {
    LogOk ("Test 1 PASSED. Hash matches: {0}" -f $hash)
} else {
    LogErr ("Test 1 FAILED. injected={0} fetched={1}" -f $hash, $verify)
}

# ---- 10. test 2: encrypted + erasure coded ----
Log "Test 2: encrypted + erasure coded (k=4 m=2) inject and fetch ..."
$keyFile = "/tmp/icss_key.bin"
Invoke-Ssh -TargetIp $vmIps[0] -Command ("openssl rand -out {0} 32" -f $keyFile) | Out-Null

Invoke-Ssh -TargetIp $vmIps[0] -Command ("cd ~/icss && ./icss inject {0} {1}:{2} --ring-id {3} --chunk-size {4} --data-shards 4 --parity-shards 2 --key {5}" -f $testFile, $vmIps[0], $listenPort, $ringId, $chunkSize, $keyFile) | ForEach-Object { Write-Host $_ }
Start-Sleep -Seconds 20

Invoke-Ssh -TargetIp $vmIps[1] -Command ("cd ~/icss && ./icss fetch {0} /tmp/icss_restored_ec.bin {1}:{2} --ring-id {3} --key {4}" -f $hash, $vmIps[1], $listenPort, $ringId, $keyFile) | ForEach-Object { Write-Host $_ }

$verifyEcOut = Invoke-Ssh -TargetIp $vmIps[1] -Command "cd ~/icss && ./icss hash /tmp/icss_restored_ec.bin"
$verifyEc = ($verifyEcOut | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -First 1)

if ($hash -eq $verifyEc) {
    LogOk ("Test 2 PASSED. Encrypted erasure-coded round trip OK: {0}" -f $hash)
} else {
    LogErr ("Test 2 FAILED. injected={0} fetched={1}" -f $hash, $verifyEc)
}

# ---- 11. report node status ----
foreach ($ip in $vmIps) {
    $st = Invoke-Ssh -TargetIp $ip -Command ("cd ~/icss && ./icss status {0}:{1} --ring-id {2}" -f $ip, $listenPort, $ringId)
    Log ("status {0}: {1}" -f $ip, ($st -join " "))
}

Write-Host ""
LogOk "Deployment and tests finished."
Log ("Node IPs: {0}" -f ($vmIps -join ", "))
Log ("Manual access: ssh -i {0} {1}@<IP>" -f $SshKeyPath, $VmUser)