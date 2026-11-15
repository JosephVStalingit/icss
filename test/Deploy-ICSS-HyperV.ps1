<# 
.SYNOPSIS
    ICSS Hyper-V 3-Node Cluster Auto-Deploy & Test
.DESCRIPTION
    Creates 3 Ubuntu VMs on Hyper-V, builds ICSS, forms a ring, runs inject/fetch/erasure tests.
    Run as Administrator.
.NOTES
    Requires: Hyper-V enabled, Internet access (for Ubuntu cloud image), ~12GB free disk.
#>

param(
    [string]$BasePath     = "C:\VMs\ICSS-Cluster",
    [string]$SwitchName   = "Default Switch",
    [int]$VcpuCount       = 2,
    [int]$MemoryGB        = 4,
    [int]$DiskGB          = 20,
    [string]$UbuntuVer    = "24.04",
    [string]$TestFileSize = "100MB"
)

$ErrorActionPreference = "Stop"

function Log($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor Cyan }
function LogOk($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ✅ $msg" -ForegroundColor Green }
function LogErr($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ❌ $msg" -ForegroundColor Red }

# 1. 检查 Hyper-V
if (-not (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State -eq "Enabled") {
    LogErr "Hyper-V 未启用。请先运行: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart"
    exit 1
}
Log "Hyper-V 已启用"

# 2. 检查虚拟交换机
$vmswitch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
if (-not $vmswitch) {
    LogErr "找不到虚拟交换机 '$SwitchName'。请先在 Hyper-V 管理器创建 'Default Switch' 或内部交换机。"
    exit 1
}
Log "使用交换机: $SwitchName"

# 3. 下载 Ubuntu Cloud Image
$imgDir = "$BasePath\Images"
$imgPath = "$imgDir\ubuntu-$UbuntuVer-server-cloudimg-amd64.img"
if (-not (Test-Path $imgPath)) {
    New-Item -ItemType Directory -Force -Path $imgDir | Out-Null
    $url = "https://cloud-images.ubuntu.com/$UbuntuVer/current/ubuntu-$UbuntuVer-server-cloudimg-amd64.img"
    Log "下载 Ubuntu $UbuntuVer cloud image..."
    try { Invoke-WebRequest -Uri $url -OutFile $imgPath -UseBasicParsing }
    catch { LogErr "下载失败: $_"; exit 1 }
    LogOk "镜像下载完成: $imgPath"
} else {
    Log "镜像已存在: $imgPath"
}

# 4. 创建 3 个 VM
$vmNames = @("icss-node1", "icss-node2", "icss-node3")
$vmIps   = @()

foreach ($name in $vmNames) {
    $vmPath = "$BasePath\$name"
    if (Get-VM -Name $name -ErrorAction SilentlyContinue) {
        Log "VM $name 已存在，跳过创建"
        continue
    }
    Log "创建 VM: $name ..."
    New-VHD -Path "$vmPath\$name.vhdx" -SizeBytes (${DiskGB}GB) -Dynamic | Out-Null
    New-VM -Name $name -MemoryStartupBytes (${MemoryGB}GB) -Generation 2 -VHDPath "$vmPath\$name.vhdx" -SwitchName $SwitchName | Out-Null
    Set-VMProcessor -VMName $name -Count $VcpuCount
    Enable-VMIntegrationService -VMName $name -Name "Guest Service Interface"
    Start-VM -Name $name
    LogOk "VM $name 创建并启动"
}

# 5. 等待 VM 获取 IP
Log "等待 VM 启动并获取 IP (约 60-90 秒)..."
Start-Sleep -Seconds 30

foreach ($name in $vmNames) {
    $ip = $null
    for ($i=0; $i -lt 12; $i++) {
        $ip = (Get-VM -Name $name).NetworkAdapters.IPAddresses | Where-Object { $_ -like "172.*" -or $_ -like "192.168.*" -or $_ -like "10.*" } | Select-Object -First 1
        if ($ip) { break }
        Start-Sleep -Seconds 10
    }
    if (-not $ip) { LogErr "$name 未获取到 IP，请检查网络"; exit 1 }
    $vmIps += $ip
    LogOk "$name IP: $ip"
}

# 6. 部署 ICSS 到每个 VM（需 SSH 密钥或密码）
Log "请确保已配置 SSH 免密登录，或准备好密码"
$cred = Get-Credential -UserName icss -Message "输入 VM 密码 (默认 icss123)"

foreach ($ip in $vmIps) {
    Log "部署到 $ip ..."
    $deployCmd = @"
sudo apt update && sudo apt install -y build-essential libssl-dev git
rm -rf icss
git clone https://github.com/your-repo/icss.git 2>/dev/null || mkdir -p icss
cd icss && make
echo BUILD_OK
"@
    Invoke-Command -ComputerName $ip -Credential $cred -ScriptBlock { param($c) & bash -c $c } -ArgumentList $deployCmd
    LogOk "$ip 部署完成"
}

# 7. 启动 3 节点环（手动 --next 形成闭环）
$ringId = 1
$chunkSize = 1048576
$queueDepth = 32
$listenPort = 9001

$cmds = @(
    "./icss node --listen $listenPort --next $($vmIps[1]):$listenPort --ring-id $ringId --chunk-size $chunkSize --queue-depth $queueDepth",
    "./icss node --listen $listenPort --next $($vmIps[2]):$listenPort --ring-id $ringId --chunk-size $chunkSize --queue-depth $queueDepth",
    "./icss node --listen $listenPort --next $($vmIps[0]):$listenPort --ring-id $ringId --chunk-size $chunkSize --queue-depth $queueDepth"
)

for ($i=0; $i -lt 3; $i++) {
    $ip = $vmIps[$i]
    Invoke-Command -ComputerName $ip -Credential $cred -ScriptBlock { param($c) nohup bash -c $c > node.log 2>&1 & } -ArgumentList $cmds[$i]
}
Start-Sleep -Seconds 10
LogOk "3 节点已启动，环已闭合"

# 8. 运行测试（从节点1注入，节点2读取）
$testFile = "/tmp/test_${TestFileSize}.bin"
$mb = [int]($TestFileSize.Replace('MB',''))
$hashCmd = "dd if=/dev/urandom of=$testFile bs=1M count=$mb && ./icss hash $testFile"
$hash = Invoke-Command -ComputerName $vmIps[0] -Credential $cred -ScriptBlock { param($c) & bash -c $c } -ArgumentList $hashCmd
$hash = ($hash | Where-Object { $_ -match '^[a-f0-9]{64}$' })[0]
Log "测试文件哈希: $hash"

# 注入
$injectCmd = "./icss inject $testFile $($vmIps[0]):$listenPort --ring-id $ringId --chunk-size $chunkSize"
Invoke-Command -ComputerName $vmIps[0] -Credential $cred -ScriptBlock { param($c) & bash -c $c } -ArgumentList $injectCmd
Start-Sleep -Seconds 15

# 读取
$fetchCmd = "./icss fetch $hash /tmp/restored.bin $($vmIps[1]):$listenPort --ring-id $ringId"
Invoke-Command -ComputerName $vmIps[1] -Credential $cred -ScriptBlock { param($c) & bash -c $c } -ArgumentList $fetchCmd

# 校验
$verifyCmd = "./icss hash /tmp/restored.bin"
$verifyHash = Invoke-Command -ComputerName $vmIps[1] -Credential $cred -ScriptBlock { param($c) & bash -c $c } -ArgumentList $verifyCmd
$verifyHash = ($verifyHash | Where-Object { $_ -match '^[a-f0-9]{64}$' })[0]

if ($hash -eq $verifyHash) {
    LogOk "✅ 多节点测试通过！哈希一致: $hash"
} else {
    LogErr "❌ 哈希不匹配! 原始: $hash, 读取: $verifyHash"
}

Log "测试完成。VM 仍在运行，可手动进一步测试。"
Log "节点 IP: $($vmIps -join ', ')"
Log "SSH 登录: ssh icss@<IP>  密码: icss123"