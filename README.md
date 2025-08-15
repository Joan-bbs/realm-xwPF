# xwPF realm 全功能一键中转脚本,快速上手搭建网络转发

[中文](README.md) | [English](README_EN.md)

---

> 🛜 **Realm 端口转发管理脚本** - 集成原生 realm 最新版全部功能 + 轻量化实现故障转移，保持极简本质,数字化操作界面一键指令操作,提高效率

## 📸 脚本界面预览 📸

<details>
<summary>点击查看界面截图</summary>

**主界面**
![主界面](https://i.mji.rip/2025/07/17/00ea7f801a89bb83cf6d4cbef4a050e5.png)

**定时任务管理**
![定时任务](https://i.mji.rip/2025/07/11/46ad95de9117d32b444097ead36f9850.png)

**转发配置管理**
![配置管理](https://i.mji.rip/2025/07/17/56557ca87dee48d112b735ad78e0f65e.png)

**负载均衡与故障转移**
![负载均衡+故障转移](https://i.mji.rip/2025/07/17/e545e7ee444a0a2aa3592d080678696c.png)

**中转网络链路测试功能**
![中转网络链路测试](https://i.mji.rip/2025/07/31/2c8a2d147b63c5299bbb7aa02068726e.png)

</details>

## 🚀 快速开始

### 一键安装

```bash
wget -qO- https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install
```

### 网络受限使用加速源,一键安装

```bash
wget -qO- https://ghfast.top/https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install
```

## 🧭 无法联网的离线安装

<details>
<summary>点击展开离线安装方法</summary>

适用于完全无法连接网络

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

- **🚀 快速体验** -一键安装快速轻量上手体验网络转发
- **🔄 故障转移** - 使用系统工具,完成自动故障检测,保持轻量化
- **⚖️ 负载均衡** - 支持轮询、IP哈希等策略，可配置权重分配
- **🕳️ 搭建隧道** - 双端realm架构支持 TLS，ws 加密传输,搭建隧道
- **✍️ 规则备注** - 清晰的备注功能,不再需要额外记忆
- **💻 直观配置系统MPTCP** - 清晰的展示MPTCP界面
- **🛜 网络链路测试** - 测试链路延迟、带宽、稳定性,路由是否绕路

- **📋 一键导出** - 打包全部文件为压缩包自由迁移(包括备注等等信息完全迁移)
- **📒 一键导入** - 识别导出的压缩包完成自由迁移
- **⏰ 定时任务** - 支持定时重启、响应ddns域名更新解析
- **🔧 智能检测** - 自动检测系统架构、端口冲突,连接可用性

- **📝 智能日志管理** - 自动限制日志大小，防止磁盘占用过大
- **🗑️ 完整卸载** - 分阶段全面清理，“轻轻的我走了，正如我轻轻的来”
- **⚡ 原生Realm全功能** - 支持最新版realm的所有原生功能
- tcp/udp协议
- ws/wss/tls加密
- 单中转多出口
- 多中转单出口
- Proxy Protocol
- MPTCP
- 指定中转机的某个入口 IP,以及指定某个出口 IP (适用于多IP情况和一入口多出口和多入口一出口的情况)
- 更多玩法参考[zhboner/realm](https://github.com/zhboner/realm)

## 🗺️ 示意图理解不同场景下工作原理(推荐阅读)

<details>
<summary><strong>单端realm架构只负责转发（常见）</strong></summary>

中转机安装realm,落地机安装业务软件

中转机realm只负责原模原样把设置的监听IP：端口收到的数据包进行转发到出口机,加密解密由业务软件负责

所以整个链路的加密协议由出口机业务软件决定

![e3c0a9ebcee757b95663fc73adc4e880.png](https://i.mji.rip/2025/07/17/e3c0a9ebcee757b95663fc73adc4e880.png)

</details>

<details>
<summary><strong>双端realm架构搭建隧道</strong></summary>

中转机安装realm,落地机要安装realm和业务软件

在realm和realm之间多套一层realm支持的加密传输

#### 所以中转机realm选择的加密,伪装域名等等,必须与落地机一致,否则无法解密

![4c1f0d860cd89ca79f4234dd23f81316.png](https://i.mji.rip/2025/07/17/4c1f0d860cd89ca79f4234dd23f81316.png)

</details>

<details>
<summary><strong>负载均衡+故障转移</strong></summary>

- 同一端口转发有多个落地机
![a9f7c94e9995022557964011d35c3ad4.png](https://i.mji.rip/2025/07/15/a9f7c94e9995022557964011d35c3ad4.png)

- 前置>多中转>单落地
![2cbc533ade11a8bcbbe63720921e9e05.png](https://i.mji.rip/2025/07/17/2cbc533ade11a8bcbbe63720921e9e05.png)

- `轮询`模式 (roundrobin)

不断切换规则组里的落地机

- `IP哈希`模式 (iphash)

基于源 IP 的哈希值，决定流量走向，保证同一 IP 的请求始终落到同一落地机

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

客户端可使用指令`while ($true) { (Invoke-WebRequest -Uri 'http://ifconfig.me/ip' -UseBasicParsing).Content; Start-Sleep -Seconds 1 }` 或 `while true; do curl -s ifconfig.me; echo; sleep 1; done` 实时监听IP变化情况,确定模式生效

</details>

<details>
<summary>
<strong>双端realm调用系统MPTCP</strong>
</summary>

MPTCP端点不是创建一张新的虚拟网卡，而是：
告诉MPTCP协议栈：这个IP地址可以用于MPTCP连接
指定路径：数据可以通过这个IP地址和对应的网卡传输
建立多路径：让一个TCP连接可以同时使用多个网络路径

**Q:为什么需要同时指定IP和网卡？**
网卡接口：系统需要知道这个IP地址对应哪个物理网卡，用于路由选择
IP地址：MPTCP协议需要知道可以使用哪些IP地址建立子流
192.168.1.100 dev eth0 subflow fullmesh = 告诉MPTCP可以通过eth0网卡的这个IP建立连接
10.0.0.50 dev eth1 subflow fullmesh = 告诉MPTCP可以通过eth1网卡的这个IP建立连接

如果想要更精细的控制，可以考虑：

服务端也设置signal端点：
精细化控制mptcp

</details>

<details>
<summary><strong>端口转发 vs 链式代理(分段代理)</strong></summary>

容易搞混的两个概念

**简单理解**

端口转发只负责把某个端口的流量转发到另一个端口

链式代理是这样

分成了两段代理链,所以又称为分段代理,二级代理（有机会再细讲配置）

**各有各的优点**看使用场景 | 注意有的机不允许安装代理 | 不过某些场景链式会很灵活

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
| `iproute2` | MPTCP端点管理 | ✅ |

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
├── /etc/sysctl.d/
│   └── 90-enable-MPTCP.conf     # MPTCP系统配置文件
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
- "https://ghfast.top/""https://ghproxy.gpnu.org/""https://gh.222322.xyz/"  -提供公益加速源
- 所有为项目提供反馈和建议的用户

---

**⭐ 如果这个项目对您有帮助，请给个 Star 支持一下！**

[![Star History Chart](https://api.star-history.com/svg?repos=zywe03/realm-xwPF&type=Date)](https://www.star-history.com/#zywe03/realm-xwPF&Date)