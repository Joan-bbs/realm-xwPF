# xwPF realm 全功能一键脚本，助你快速部署和配置 realm，满足网络转发需求
# xwPF realm: A full-featured one-click script for quickly deploying and configuring realm to meet network relay needs.

[中文](#中文版) | [English](#english-version)

---

## 中文版

> 🚀 **Realm 端口转发智能管理脚本** - 集成原生 realm 最新版全部功能 + 轻量化实现故障转移，保持极简本质,数字化操作界面一键指令操作,提高效率

## 📸 界面预览

<details>
<summary>点击查看界面截图</summary>

**主界面**
![主界面](https://i.mji.rip/2025/07/15/6b3455876c973a3988dc9c4c3d99e5f7.png)

**定时任务管理**
![定时任务](https://i.mji.rip/2025/07/11/46ad95de9117d32b444097ead36f9850.png)

**转发配置管理**
![配置管理](https://i.mji.rip/2025/07/15/324a19f8ca8a758e760662672d14ad35.png)

**负载均衡与故障转移**
![负载均衡+故障转移](https://i.mji.rip/2025/07/15/01c21c9988c3b2d91edce364be65d445.png)

</details>

## 🚀 快速开始（网络受限环境看下文）

### 一键安装

**方法一：使用 curl**
```bash
curl -fsSL https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install
```

**方法二：使用 wget**
```bash
wget -qO- https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install
```

## 🧭 离线安装（网络受限环境）

<details>
<summary>点击展开离线安装方法</summary>

适用于无法直接访问 GitHub 的服务器环境：(only ipv6等等)

**下载必要文件**

在有网络的设备上下载以下文件：
- **脚本文件下载**：[xwPF.sh](https://github.com/zywe03/realm-xwPF/raw/main/xwPF.sh) (右键点击 → 另存为)
- **Realm 程序下载**（根据系统架构选择）：

| 架构 | 适用系统 | 下载链接 | 检测命令 |
|------|----------|----------|----------|
| x86_64 | 常见64位系统 | [realm-x86_64-unknown-linux-gnu.tar.gz](https://github.com/zhboner/realm/releases/download/v2.7.0/realm-x86_64-unknown-linux-gnu.tar.gz) | `uname -m` 显示 `x86_64` |
| aarch64 | ARM64系统 | [realm-aarch64-unknown-linux-gnu.tar.gz](https://github.com/zhboner/realm/releases/download/v2.7.0/realm-aarch64-unknown-linux-gnu.tar.gz) | `uname -m` 显示 `aarch64` |
| armv7 | ARM32系统（如树莓派） | [realm-armv7-unknown-linux-gnueabihf.tar.gz](https://github.com/zhboner/realm/releases/download/v2.7.0/realm-armv7-unknown-linux-gnueabihf.tar.gz) | `uname -m` 显示 `armv7l` 或 `armv6l` |

随便创建一个目录放置脚本和压缩包文件,bash指令启动脚本选择**1. 安装配置**会优先自动检测**脚本同目录下的realm文件**进行安装

</details>

## ✨ 核心特性

- **🚀 一键安装** - 单条命令快速上手，支持网络受限环境下**离线安装**
- **🔄 故障转移** - 使用系统工具,完成自动故障检测,保持轻量化
- **⚖️ 负载均衡** - 支持轮询、IP哈希等策略，可配置权重分配
- **🕳️ 搭建隧道** - 双端realm架构支持 TLS，ws 加密传输搭建正向隧道
- **✅ 支持多种虚拟化** - 自动检测和适配

- **📊 可视化界面** - 简洁的数字选择菜单，无需记忆复杂命令
- **📋 导出/导入配置文件** - 查看当前配置复制导出、识别同目录 JSON 配置文件导入
- **⏰ 定时任务** - 支持定时重启、响应ddns域名更新解析
- **🔧 智能检测** - 自动检测系统架构、依赖工具、端口冲突

- **🔍 连通性测试** - 自动测试配置的连接可用性
- **📝 智能日志管理** - 自动限制日志大小，防止磁盘占用过大
- **🗑️ 完整卸载** - 分阶段全面清理，“轻轻的我走了，正如我轻轻的来”
- **⚡ 原生Realm全功能** - 支持最新版realm的所有原生功能
- tcp/udp协议
- 单中转多出口
- 多中转单出口
- 指定监听某个 IP 中转
- 更多玩法参考[zhboner/realm](https://github.com/zhboner/realm)

## 🗺️ 示意图理解不同场景下工作原理(推荐)

<details>
<summary><strong>单端realm架构只负责转发（常见）</strong></summary>

中转机安装realm,出口机安装业务软件

中转机realm只负责原模原样把设置的监听IP：端口收到的数据包进行转发到出口机,加密解密由业务软件负责

所以整个链路的加密协议由出口机业务软件决定

![e3c0a9ebcee757b95663fc73adc4e880.png](https://i.mji.rip/2025/07/17/e3c0a9ebcee757b95663fc73adc4e880.png)

</details>

<details>
<summary><strong>双端realm架构搭建隧道</strong></summary>

中转机安装realm,出口机要安装realm和业务软件

在realm和realm之间多套一层realm支持的加密传输

#### 所以中转机realm选择的加密,伪装域名等等,必须与落地机一致,否则无法解密

![4c1f0d860cd89ca79f4234dd23f81316.png](https://i.mji.rip/2025/07/17/4c1f0d860cd89ca79f4234dd23f81316.png)

</details>

<details>
<summary><strong>负载均衡+故障转移</strong></summary>

- 同一端口转发有多个出口机
![a9f7c94e9995022557964011d35c3ad4.png](https://i.mji.rip/2025/07/15/a9f7c94e9995022557964011d35c3ad4.png)

- 前置>多中转>单落地
![2cbc533ade11a8bcbbe63720921e9e05.png](https://i.mji.rip/2025/07/17/2cbc533ade11a8bcbbe63720921e9e05.png)

- `轮询`模式 (roundrobin)

不断切换规则组里的出口机

- `IP哈希`模式 (iphash)

基于源 IP 的哈希值，决定流量走向，保证同一 IP 的请求始终落到同一出口机

- 权重即分配概率

- 故障转移

检测到某个出口故障，暂时移出负载均衡列表，恢复之后会自动添加进负载均衡列表

原生realm暂不支持故障转移

- 脚本的实现原理
```
1. systemd定时器触发 (每4秒)
   ↓
2. 执行健康检查脚本
   ↓
3. 读取规则配置文件
   ↓
4. 对每个目标执行TCP连通性检测
   ├── nc -z -w3 target port
   └── 备用: telnet target port
   ↓
5. 更新健康状态文件（原子更新）
   ├── 成功: success_count++, fail_count=0
   └── 失败: fail_count++, success_count=0
   ↓
6. 判断状态变化
   ├── 连续失败2次 → 标记为故障
   └── 连续成功2次+冷却期120秒(避免抖动频繁切换) → 标记为恢复
   ↓
7. 如有状态变化，创建更新标记文件
```

客户端可使用指令`while ($true) { (Invoke-WebRequest -Uri 'http://ifconfig.me/ip' -UseBasicParsing).Content; Start-Sleep -Seconds 1 }` 或 `while true; do curl -s ifconfig.me; echo; sleep 1; done` 实时监听IP变化情况

</details>

<details>
<summary><strong>端口转发 vs 链式代理(分段代理)</strong></summary>

容易搞混的两个概念

**简单理解**

端口转发只负责把某个端口的流量转发到另一个端口

链式代理是这样

分成了两段代理链,所以又称为分段代理,二级代理（有机会再细讲配置）

**各有各的优点**看使用场景 | 注意有的机不允许安装代理(遵循当地法律法规) | 不过某些场景链式会很灵活

| 链式代理 (Chained Proxy) | 端口转发 (Port Forwarding) |
| :------------------- | :--------------------- |
| 链路的机都要安装代理软件           | 中转机安装转发,出口机安装代理        |
| 配置文件复杂度较高            | 配置文件复杂度低（L4层转发）        |
| 会有每跳解包/封包开销          | 原生 TCP/UDP 透传，理论上更快    |
| 出站控制分流更精确（每跳配置出口）    | 难出站控制                  |

</details>

### 依赖工具
原则优先**Linux 原生轻量化工具**，保持系统干净轻量化

| 工具 | 用途 | 自动安装 |
|------|------|------|
| `curl` | 下载和IP获取 | ✅ |
| `wget` | 备用下载工具 | ✅ |
| `tar` | 解压缩工具 | ✅ |
| `systemctl` |总指挥协调工作 | ✅ |
| `bc` | 数值计算 | ✅ |
| `nc` | 网络连接测试 | ✅ |
| `grep`/`cut` | 文本处理识别 | ✅ |
| `inotify` | 标记文件 | ✅ |

## 📁 文件结构

安装完成后的文件组织结构：

```
📦 系统文件
├── /usr/local/bin/
│   ├── realm                    # Realm 主程序
│   ├── xwPF.sh                  # 管理脚本主体
│   └── pf                       # 快捷启动命令
│
├── /etc/realm/                  # 配置目录
│   ├── manager.conf             # 状态管理文件（核心）
│   ├── config.json              # Realm 工作配置文件
│   ├── rules/                   # 转发规则目录
│   │   ├── rule-1.conf          # 规则1配置
│   │   ├── rule-2.conf          # 规则2配置
│   │   └── ...
│   ├── cron/                    # 定时任务目录
│   │   └── tasks.conf           # 任务配置文件
│   └── health/                  # 健康检查目录（故障转移）
│       └── health_status.conf   # 健康状态文件
│
├── /etc/systemd/system/
│   ├── realm.service            # 主服务文件
│   ├── realm-health-check.service  # 健康检查服务
│   └── realm-health-check.timer    # 健康检查定时器
│
└── /var/log/
    └── realm.log                # 服务日志文件
```

## 🤝 技术支持

- **其他开源项目：** [https://github.com/zywe03](https://github.com/zywe03)
- **作者主页：** [https://zywe.de](https://zywe.de)
- **问题反馈：** [GitHub Issues](https://github.com/zywe03/realm-xwPF/issues)

## 🙏 致谢

- [zhboner/realm](https://github.com/zhboner/realm) - 提供核心的 Realm 程序
- 所有为项目提供反馈和建议的用户

---

**⭐ 如果这个项目对您有帮助，请给个 Star 支持一下！**

[![Star History Chart](https://api.star-history.com/svg?repos=zywe03/realm-xwPF&type=Date)](https://www.star-history.com/#zywe03/realm-xwPF&Date)

---

## English Version

> 🚀 **Realm Port Forwarding Intelligent Management Script** – Integrates all native features of the latest Realm version + lightweight failover implementation, maintains minimalist essence, digitized operation interface with one-click commands for improved efficiency

## 📸 Interface Preview

<details>
<summary>Click to view interface screenshots</summary>

**Main Interface**
![Main Interface](https://i.mji.rip/2025/07/15/6b3455876c973a3988dc9c4c3d99e5f7.png)

**Scheduled Task Management**
![Scheduled Tasks](https://i.mji.rip/2025/07/11/46ad95de9117d32b444097ead36f9850.png)

**Forwarding Configuration Management**
![Configuration Management](https://i.mji.rip/2025/07/15/324a19f8ca8a758e760662672d14ad35.png)

**Load Balancing & Failover**
![Load Balancing + Failover](https://i.mji.rip/2025/07/15/01c21c9988c3b2d91edce364be65d445.png)

</details>

## 🚀 Quick Start (For Network-Restricted Environments, See Below)

### One-Click Installation

**Method 1: Using curl**
```bash
curl -fsSL https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install
```

**Method 2: Using wget**
```bash
wget -qO- https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install
```

## 🧭 Offline Installation (Network-Restricted Environments)

<details>
<summary>Click to expand offline installation methods</summary>

Suitable for server environments that cannot directly access GitHub: (only ipv6, etc.)

**Download Required Files**

Download the following files on a device with network access:
- **Script File Download**: [xwPF.sh](https://github.com/zywe03/realm-xwPF/raw/main/xwPF.sh) (Right-click → Save as)
- **Realm Program Download** (choose according to system architecture):

| Architecture | Applicable Systems | Download Link | Detection Command |
|--------------|-------------------|---------------|-------------------|
| x86_64 | Common 64-bit systems | [realm-x86_64-unknown-linux-gnu.tar.gz](https://github.com/zhboner/realm/releases/download/v2.7.0/realm-x86_64-unknown-linux-gnu.tar.gz) | `uname -m` shows `x86_64` |
| aarch64 | ARM64 systems | [realm-aarch64-unknown-linux-gnu.tar.gz](https://github.com/zhboner/realm/releases/download/v2.7.0/realm-aarch64-unknown-linux-gnu.tar.gz) | `uname -m` shows `aarch64` |
| armv7 | ARM32 systems (like Raspberry Pi) | [realm-armv7-unknown-linux-gnueabihf.tar.gz](https://github.com/zhboner/realm/releases/download/v2.7.0/realm-armv7-unknown-linux-gnueabihf.tar.gz) | `uname -m` shows `armv7l` or `armv6l` |

Create any directory and place the script and compressed package files there. When starting with bash command and selecting **1. Install Configuration**, it will automatically detect and install the **realm file in the script's directory** first.

</details>

## ✨ Core Features

- **🚀 One-Click Installation** - Single command for quick setup, supports **offline installation** for network-restricted environments
- **🔄 Failover** - Uses system tools to achieve automatic failure detection while maintaining lightweight design
- **⚖️ Load Balancing** - Supports round-robin, IP hash strategies with configurable weight distribution
- **🕳️ Tunnel Building** - Dual-realm architecture supports TLS, ws encrypted transmission for forward tunnel construction
- **✅ Multiple Virtualization Support** - Automatic detection and adaptation

- **📊 Visual Interface** - Clean numeric selection menu, no need to memorize complex commands
- **📋 Export/Import Configuration Files** - View current configuration for copy/export, recognize JSON configuration files in the same directory for import
- **⏰ Scheduled Tasks** - Support for scheduled restarts, responding to DDNS domain update resolution
- **🔧 Intelligent Detection** - Automatic detection of system architecture, dependency tools, port conflicts

- **🔍 Connectivity Testing** - Automatic testing of configured connection availability
- **📝 Intelligent Log Management** - Automatic log size limitation to prevent excessive disk usage
- **🗑️ Complete Uninstallation** - Phased comprehensive cleanup, "I leave gently, just as I came gently"
- **⚡ Full Native Realm Functionality** - Supports all native features of the latest realm version
- tcp/udp protocols
- Single relay to multiple exits
- Multiple relays to single exit
- Specify listening on a specific IP for relay
- More usage patterns refer to [zhboner/realm](https://github.com/zhboner/realm)

## 🗺️ Diagrams to Understand Working Principles in Different Scenarios (Recommended)

<details>
<summary><strong>Single-End Realm Architecture - Forwarding Only (Common)</strong></summary>

Relay server installs realm, exit server installs business software.

The relay server's realm only forwards data packets received on the configured listening IP:port to the exit server as-is. Encryption/decryption is handled by business software.

Therefore, the encryption protocol for the entire chain is determined by the exit server's business software.

![e3c0a9ebcee757b95663fc73adc4e880.png](https://i.mji.rip/2025/07/17/e3c0a9ebcee757b95663fc73adc4e880.png)

</details>

<details>
<summary><strong>Dual-End Realm Architecture - Building Tunnels</strong></summary>

Relay server installs realm, exit server needs to install realm and business software.

An additional layer of realm-supported encrypted transmission is added between realm instances.

#### Therefore, the encryption chosen by the relay server's realm, masquerading domains, etc., must be consistent with the landing server, otherwise decryption will fail.

![4c1f0d860cd89ca79f4234dd23f81316.png](https://i.mji.rip/2025/07/17/4c1f0d860cd89ca79f4234dd23f81316.png)

</details>

<details>
<summary><strong>Load Balancing + Failover</strong></summary>

- Multiple exit servers for the same port forwarding
![a9f7c94e9995022557964011d35c3ad4.png](https://i.mji.rip/2025/07/15/a9f7c94e9995022557964011d35c3ad4.png)

- Frontend > Multiple Relays > Single Landing
![2cbc533ade11a8bcbbe63720921e9e05.png](https://i.mji.rip/2025/07/17/2cbc533ade11a8bcbbe63720921e9e05.png)

- `Round Robin` mode (roundrobin)

Continuously switches between exit servers in the rule group.

- `IP Hash` mode (iphash)

Based on the hash value of the source IP, determines traffic direction, ensuring requests from the same IP always go to the same exit server.

- Weight represents allocation probability

- Failover

When a certain exit is detected as failed, it's temporarily removed from the load balancing list. It will be automatically added back to the load balancing list after recovery.

Native realm does not currently support failover.

- Script's Implementation Principle
```
1. systemd timer trigger (every 4 seconds)
   ↓
2. Execute health check script
   ↓
3. Read rule configuration files
   ↓
4. Perform TCP connectivity detection for each target
   ├── nc -z -w3 target port
   └── Backup: telnet target port
   ↓
5. Update health status file (atomic update)
   ├── Success: success_count++, fail_count=0
   └── Failure: fail_count++, success_count=0
   ↓
6. Determine status changes
   ├── 2 consecutive failures → Mark as failed
   └── 2 consecutive successes + 120s cooldown (avoid jitter) → Mark as recovered
   ↓
7. If status changes, create update marker file
```

Clients can use the command `while ($true) { (Invoke-WebRequest -Uri 'http://ifconfig.me/ip' -UseBasicParsing).Content; Start-Sleep -Seconds 1 }` or `while true; do curl -s ifconfig.me; echo; sleep 1; done` to monitor IP changes in real-time.

</details>

<details>
<summary><strong>Port Forwarding vs Chain Proxy (Segmented Proxy)</strong></summary>

Two concepts that are easily confused.

**Simple Understanding**

Port forwarding only handles forwarding traffic from one port to another port.

**Chain Proxy is like this**

It's divided into two proxy segments, hence also called segmented proxy or secondary proxy (detailed configuration will be covered later).

**Each has its own advantages** - depends on the use case | Note that some servers don't allow proxy installation (comply with local laws and regulations) | However, chain proxy can be very flexible in certain scenarios

| Chain Proxy | Port Forwarding |
| :---------- | :-------------- |
| All servers in the chain need proxy software installed | Relay server installs forwarding, exit server installs business software |
| Higher configuration file complexity | Lower configuration file complexity (L4 layer forwarding) |
| Overhead from unpacking/packing at each hop | Native TCP/UDP passthrough, theoretically faster |
| More precise outbound control and traffic splitting (configure exit at each hop) | Difficult outbound control |

</details>

### Dependency Tools
Principle: prioritize **Linux native lightweight tools**, keeping the system clean and lightweight

| Tool | Purpose | Auto Install |
|------|---------|--------------|
| `curl` | Download and IP retrieval | ✅ |
| `wget` | Backup download tool | ✅ |
| `tar` | Compression/decompression tool | ✅ |
| `systemctl` | Commander coordinating work | ✅ |
| `bc` | Numerical calculations | ✅ |
| `nc` | Network connection testing | ✅ |
| `grep`/`cut` | Text processing and recognition | ✅ |
| `inotify` | Marker files | ✅ |

## 📁 File Structure

File organization structure after installation:

```
📦 System Files
├── /usr/local/bin/
│   ├── realm                    # Realm main program
│   ├── xwPF.sh                  # Management script main body
│   └── pf                       # Quick start command
│
├── /etc/realm/                  # Configuration directory
│   ├── manager.conf             # Status management file (core)
│   ├── config.json              # Realm working configuration file
│   ├── rules/                   # Forwarding rules directory
│   │   ├── rule-1.conf          # Rule 1 configuration
│   │   ├── rule-2.conf          # Rule 2 configuration
│   │   └── ...
│   ├── cron/                    # Scheduled tasks directory
│   │   └── tasks.conf           # Task configuration file
│   └── health/                  # Health check directory (failover)
│       └── health_status.conf   # Health status file
│
├── /etc/systemd/system/
│   ├── realm.service            # Main service file
│   ├── realm-health-check.service  # Health check service
│   └── realm-health-check.timer    # Health check timer
│
└── /var/log/
    └── realm.log                # Service log file
```

## 🤝 Technical Support

- **Other Open Source Projects:** [https://github.com/zywe03](https://github.com/zywe03)
- **Author Homepage:** [https://zywe.de](https://zywe.de)
- **Issue Feedback:** [GitHub Issues](https://github.com/zywe03/realm-xwPF/issues)

## 🙏 Acknowledgments

- [zhboner/realm](https://github.com/zhboner/realm) - Providing the core Realm program
- All users who provided feedback and suggestions for the project

---

**⭐ If this project helps you, please give it a Star for support!**

[![Star History Chart](https://api.star-history.com/svg?repos=zywe03/realm-xwPF&type=Date)](https://www.star-history.com/#zywe03/realm-xwPF&Date)
