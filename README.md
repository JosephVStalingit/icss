# ICSS

ICSS 是面向稳定在线计算集群的去中心化在线式环流存储系统。数据不落地到任何节点磁盘，只以 TCP 链路在途数据加节点内存转发队列的形态持续循环流动。所有计算节点地位完全对等，通过 UDP 广播发现邻居并自动组成闭合环流。

## 已实现能力

- **纯中继零落地**：转发节点只做逐跳 SHA-256 校验、环流计数和转发，缓冲区转发完成立即释放。本地只持久化纯哈希元数据索引，不含任何分片内容。
- **自动发现与拓扑**：UDP 广播心跳（5 秒周期，30 秒超时判离线），按 IP 字典序加端口升序全局唯一排序，各节点独立计算得到一致拓扑，无需协商。`--next` 可手动指定下游用于调试。
- **平滑拓扑切换**：邻居变化时先建立新连接、成功后再关闭旧连接（先建后断），切换过程环流不中断。
- **两级反压**：下游队列 80% 水位向上游发送暂停帧、30% 水位发送恢复帧，信号逐跳传播；队列满时丢弃新帧而不是阻塞整环。
- **Reed-Solomon 纠删码**：注入端按 k 数据片加 m 校验片分组编码，每片独立入环。转发节点只透传校验片，不做解码。读取端任意收集 k 片即可重建一组，最多可容忍 m 片缺失。
- **端到端加密**：AES-256-GCM，逐分片独立 IV。AAD 绑定不可变身份字段（环 ID、分片序号、文件哈希、长度），中继无法篡改这些字段而不破坏认证。中继节点不持有密钥、不解密。
- **旁路复制读取**：读取只复制一份分片到本地，原分片继续沿环流动，读取不消耗存储态。
- **多环并行**：`--ring-id` 隔离逻辑环，不同数据集独立环流互不干扰。

## 能力边界（重要）

这是**在线式永久存储**，不是持久化存储系统：

- 前提是所有节点与链路 7x24 稳定在线。**全集群断电、进程崩溃、网络分区会导致在途数据丢失。**
- 内存中每个分片默认只有一份副本。单个节点掉线时，恰好只存在于该节点内存中的那部分分片会丢失。纠删码可以让一组中的 m 片缺失仍可重建，但**不能替代副本**，也无法覆盖"整个环流同时消失"的场景。
- 哈希索引只记录节点曾观察到的文件哈希元数据，**不证明载荷在节点重启后仍然存在**。索引文件绝不含明文或密文分片内容。
- 不要用本系统保存唯一副本或不可重建的数据。
- 尚未在真实万兆/InfiniBand 集群上验证吞吐、延迟和数月长稳能力。当前实现使用线程加阻塞 socket，不是 epoll/kqueue 单线程事件循环。

## 平台构建

共享 C99 源码 `icss.c`，平台分别构建。依赖 OpenSSL 3.x 的 `libcrypto`。

### Unix / Linux / macOS

需要 C99 编译器、GNU Make、OpenSSL 开发头文件与库。

```sh
make
./icss help
./icss node --listen 9001
./icss hash ./dataset.bin
sudo make install
make clean
```

可通过 Make 命令行变量（例如 `make CC=clang CFLAGS="-std=c99 -O2 -Wall"`）覆盖编译器和编译选项，也可设置 `LDFLAGS`、`LDLIBS`、`PREFIX`。

### Windows

推荐使用 MSYS2 MINGW64 GCC 与 OpenSSL。安装包后在 MSYS2 MINGW64 终端运行：

```sh
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make
```

在 Windows 命令提示符或 PowerShell 中，确保 GCC 在 `PATH`，然后运行：

```bat
build_windows.bat
icss.exe help
```

默认 OpenSSL 路径为 `C:\msys64\mingw64`，可用 `OPENSSL_ROOT` 环境变量覆盖。运行时需确保 `libcrypto-3-x64.dll` 可从 `PATH` 找到。

## Windows 安装（添加到系统 PATH）

### 方法一：手动添加（推荐）

将 `icss.exe` 和 `libcrypto-3-x64.dll` 复制到任意目录（如 `C:\Tools\ICSS\`），然后添加到系统 PATH：

1. 按 `Win+S` 搜索 "环境变量" → 点击 "编辑系统环境变量"
2. 点击 "环境变量" → 在"系统变量"区找到 `Path` → 编辑 → 新建
3. 添加路径：`C:\Tools\ICSS`（你的实际目录）
4. 确定保存，**重新打开终端**生效

或使用命令行（需管理员权限）：
```cmd
setx /M PATH "%PATH%;C:\Tools\ICSS"
```

### 方法二：当前目录直接运行

确保 `libcrypto-3-x64.dll` 与 `icss.exe` 同目录：
```cmd
icss.exe help
```

### 依赖库

- `libcrypto-3-x64.dll` - OpenSSL 3.x 加密库（必需）
- 来源：MSYS2 `mingw-w64-x86_64-openssl` 包，路径 `C:\msys64\mingw64\bin\`

## CLI

```text
icss help [command]
icss version
icss protocol
icss hash <file>
icss key-check <key-file>
icss selftest
icss erasure-check [--data-shards K] [--parity-shards M] [--lost N]
icss node --listen PORT [--broadcast-port PORT] [--chunk-size BYTES]
           [--queue-depth N] [--ring-id ID] [--index-path PATH] [--next IP:PORT]
icss inject FILE IP:PORT [--key KEYFILE] [--ring-id ID] [--chunk-size BYTES]
                   [--data-shards K] [--parity-shards M]
icss fetch FILE_SHA256 OUTPUT_FILE IP:PORT [--key KEYFILE] [--ring-id ID]
icss status IP:PORT [--ring-id ID] [--list-files]
```

### node

```sh
icss node --listen 9001 --broadcast-port 7777 --chunk-size 16777216 \
          --queue-depth 32 --ring-id 0 --index-path ./icss_index.dat
```

不带 `--next` 时使用 UDP 自动发现组成环。指定 `--next` 则固定下游地址，用于调试或跨广播域部署。

### inject

```sh
# 明文，单分片
icss inject dataset.bin 10.0.0.1:9001 --chunk-size 1048576

# 密文，k=4 数据片 + m=2 校验片，每组 6 片入环，最多容忍丢 2 片
openssl rand -out key.bin 32
icss inject dataset.bin 10.0.0.1:9001 --chunk-size 1048576 \
      --data-shards 4 --parity-shards 2 --key key.bin
```

输出文件根哈希、总分片数、分组数和纠删码参数到 stdout。

### fetch

```sh
icss fetch <64位SHA256> restored.bin 10.0.0.1:9001
icss fetch <64位SHA256> restored.bin 10.0.0.1:9001 --key key.bin
```

读取端按需收集分片：只要每组拿到 k 片就能重建，不必等齐全部 k+m 片。完成后校验整文件 SHA-256，不匹配则报错并删除输出。

### status

```sh
icss status 10.0.0.1:9001
icss status 10.0.0.1:9001 --list-files
```

单行 JSON，包含 `online_nodes`、`upstream`、`downstream`、`ring_id`、`chunk_size`、`queue_usage`、`queue_capacity`、`total_forwarded`、`dropped_frames`、`permanent_files`、`uptime`，`--list-files` 额外列出数据集哈希。

## 协议

数据帧头 144 字节（全部网络字节序），后接可变载荷：

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 4 | magic `ICSS` |
| 4 | 2 | 版本与标志（bit0 表示已加密） |
| 6 | 2 | ring_id |
| 8 | 8 | 环流跳数计数器，每跳加一 |
| 16 | 4 | chunk_id |
| 20 | 4 | total_chunks |
| 24 | 8 | file_size（原始文件长度） |
| 32 | 4 | ttl |
| 36 | 4 | chunk_size |
| 40 | 4 | payload_size |
| 44 | 32 | 文件根哈希 |
| 76 | 32 | 载荷 SHA-256 |
| 108 | 12 | AES-GCM IV |
| 120 | 16 | AES-GCM tag |
| 136 | 4 | data_shards(k)、parity_shards(m)、shard_pos、保留 |
| 140 | 4 | shard_group |

控制帧 8 字节：4 字节 magic 加操作码、标志位和 ring_id。`ICSF` 用于反压暂停/恢复，`ICSC` 用于注入/读取/状态，`ICSP` 是节点间握手。

UDP 心跳 36 字节：magic `ICSD`、16 字节节点 ID（IP 加端口的 SHA-256 前 16 字节）、IPv4 地址、TCP 端口、环 ID、时间戳。

本地索引文件格式：头 `ICIX` 加版本、环 ID、文件数，随后每个文件是 32 字节根哈希、4 字节分片数、两个 8 字节时间戳，再跟该文件全部分片的 32 字节哈希。**只含哈希元数据。**

`icss protocol` 可以打印完整字段布局。

## 信号控制

Unix 下 SIGINT 和 SIGTERM 停止节点并持久化索引，SIGUSR1 打印运行状态到 stderr。Windows 使用 Ctrl+C 或控制台关闭。

## 退出码

0 成功，1 参数错误，2 运行时错误。结果输出到 stdout，错误与进度输出到 stderr。

## 常见问题与最佳实践

**问：数据真的永久吗？**
只在所有节点与链路持续在线的稳态下成立。任一节点进程崩溃都会丢失只存在于它内存中的那部分分片。纠删码让每组能容忍 m 片缺失，但不是备份。

**问：能存训练数据集做 checkpoint 吗？**
可以作为训练数据集的流式读取层，但 checkpoint 需要可重建路径。请确保 checkpoint 同时存在别处。

**问：多个数据集怎么隔离？**
用不同的 `--ring-id`。不同环的节点互不通信，互不干扰。

**问：如何验证纠删码容错？**
`icss erasure-check --data-shards 4 --parity-shards 2 --lost 2` 会实际丢弃 2 片并验证重建结果。

**问：为什么我的 fetch 一直等？**
读取需要足够分片流经接入节点。检查 `status` 的 `permanent_files` 是否包含目标哈希，以及接入节点是否在环上。120 秒无数据会超时退出。

**问：内存占用怎么控制？**
`--queue-depth` 控制下游队列深度，`--chunk-size` 控制单帧大小。队列深度乘以分片大小大致是每个节点的稳态内存占用上限。

## Hyper-V 环流存储可行性测试

### 测试环境搭建

在 Hyper-V 中创建 3 个 Ubuntu VM（或 Windows），模拟 3 节点环形集群：

```powershell
# 创建 3 个 Gen2 VM，每个 2 vCPU / 4GB RAM / 20GB 磁盘
New-VM -Name "icss-node1" -MemoryStartupBytes 4GB -Generation 2 -NewVHDPath "C:\VMs\icss-node1.vhdx" -NewVHDSizeBytes 20GB -Switch "Default Switch"
New-VM -Name "icss-node2" -MemoryStartupBytes 4GB -Generation 2 -NewVHDPath "C:\VMs\icss-node2.vhdx" -NewVHDSizeBytes 20GB -Switch "Default Switch"
New-VM -Name "icss-node3" -MemoryStartupBytes 4GB -Generation 2 -NewVHDPath "C:\VMs\icss-node3.vhdx" -NewVHDSizeBytes 20GB -Switch "Default Switch"
```

### 网络配置

确保 VM 间网络互通（Default Switch 通常自动 NAT）：

```bash
# 每个 VM 内查看 IP
ip addr show eth0
# 假设 IP 分别为：172.17.0.2, 172.17.0.3, 172.17.0.4
```

### 编译部署（每个 VM）

```bash
# 安装依赖
sudo apt update && sudo apt install -y build-essential libssl-dev git

# 克隆/复制源码
git clone <your-repo> icss || scp -r icss/ user@vm:/home/user/

# 编译
cd icss && make

# 验证
./icss version
```

### 启动 3 节点环（手动指定下游，避免广播依赖）

**节点 1 (172.17.0.2:9001) → 节点 2**
```bash
./icss node --listen 9001 --next 172.17.0.3:9001 --ring-id 1 --chunk-size 1048576 --queue-depth 16
```

**节点 2 (172.17.0.3:9001) → 节点 3**
```bash
./icss node --listen 9001 --next 172.17.0.4:9001 --ring-id 1 --chunk-size 1048576 --queue-depth 16
```

**节点 3 (172.17.0.4:9001) → 节点 1（闭环）**
```bash
./icss node --listen 9001 --next 172.17.0.2:9001 --ring-id 1 --chunk-size 1048576 --queue-depth 16
```

### 功能验证

**1. 基础注入/读取测试**
```bash
# 在任意节点或客户端机器生成测试数据
dd if=/dev/urandom of=test_100mb.bin bs=1M count=100
./icss hash test_100mb.bin
# 记录输出的 SHA256

# 注入到节点 1
./icss inject test_100mb.bin 172.17.0.2:9001 --ring-id 1 --chunk-size 1048576

# 从节点 2 读取验证
./icss fetch <SHA256> restored.bin 172.17.0.3:9001 --ring-id 1
sha256sum restored.bin  # 对比原始哈希
```

**2. 纠删码容错测试**
```bash
# 生成密钥
openssl rand -out key.bin 32

# 注入 k=2, m=1（3 片，容忍 1 片丢失）
./icss inject test_100mb.bin 172.17.0.2:9001 --ring-id 1 \
  --chunk-size 1048576 --data-shards 2 --parity-shards 1 --key key.bin

# 读取验证
./icss fetch <SHA256> restored.bin 172.17.0.3:9001 --ring-id 1 --key key.bin
```

**3. 单节点故障模拟**
```bash
# 观察 status
./icss status 172.17.0.2:9001 --ring-id 1 --list-files

# 强制关闭节点 2 进程（Ctrl+C）
# 再次尝试读取 - 应该仍能从节点 1/3 恢复（纠删码允许）
./icss fetch <SHA256> restored2.bin 172.17.0.1:9001 --ring-id 1 --key key.bin
```

**4. 长稳压力测试**
```bash
# 持续注入多个文件，监控内存/队列
for i in {1..10}; do
  dd if=/dev/urandom of=data_$i.bin bs=1M count=50
  ./icss inject data_$i.bin 172.17.0.2:9001 --ring-id 1 --chunk-size 1048576
done

# 定期查看状态
watch -n 5 './icss status 172.17.0.2:9001 --ring-id 1'
```

### 预期观测指标

| 指标 | 正常范围 | 异常判定 |
|------|----------|----------|
| `queue_usage / queue_capacity` | < 50% 稳态 | 持续 > 80% 触发反压 |
| `dropped_frames` | 0 | > 0 表示丢包/拥塞 |
| `online_nodes` | 3 | < 3 表示节点掉线 |
| `total_forwarded` | 持续增长 | 停滞表示环流中断 |
| 内存占用 | ~queue_depth × chunk_size | 超预期可能有泄漏 |

### 故障注入测试

```bash
# 网络延迟模拟（节点间）
tc qdisc add dev eth0 root netem delay 10ms loss 0.1%

# 网络分区模拟
tc qdisc add dev eth0 root netem loss 50%

# 恢复
tc qdisc del dev eth0 root
```

### 清理

```bash
# 停止所有节点（Ctrl+C 或 kill）
pkill icss

# 删除测试文件
rm -f *.bin key.bin restored*.bin
```
