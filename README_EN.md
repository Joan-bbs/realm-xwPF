# xwPF realm: A full-featured one-click relay script for quick setup of network forwarding

[中文](README.md) | [English](README_EN.md)

---

> 🛜 **Realm Port Forwarding Management Script** – Integrates all native features of the latest Realm version + lightweight failover implementation, maintains minimalist essence, digitized operation interface with one-click commands for improved efficiency

## 📸 Script Interface Preview 📸

<details>
<summary>Click to view interface screenshots</summary>

**Main Interface**
![Main Interface](https://i.mji.rip/2025/07/17/00ea7f801a89bb83cf6d4cbef4a050e5.png)

**Forwarding Configuration Management**
![Configuration Management](https://i.mji.rip/2025/07/17/56557ca87dee48d112b735ad78e0f65e.png)

**Load Balancing & Failover**
![Load Balancing + Failover](https://i.mji.rip/2025/07/17/e545e7ee444a0a2aa3592d080678696c.png)

**Relay Network Link Testing**
![Relay Network Link Testing](https://i.mji.rip/2025/07/31/2c8a2d147b63c5299bbb7aa02068726e.png)

</details>

## 🚀 Quick Start

### One-Click Installation

```bash
wget -qO- https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install
```

### Network-Restricted Environments Use Accelerated Source, One-Click Installation

```bash
wget -qO- https://ghfast.top/https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install
```

## 🧭 Completely Offline Installation

<details>
<summary>Click to expand offline installation methods</summary>

Suitable for environments that cannot connect to the network at all

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

- **🚀 Quick Experience** - One-click installation for quick lightweight hands-on experience with network forwarding
- **🔄 Failover** - Uses system tools to achieve automatic failure detection while maintaining lightweight design
- **⚖️ Load Balancing** - Supports round-robin, IP hash strategies with configurable weight distribution
- **🕳️ Tunnel Building** - Dual-realm architecture supports TLS, ws encrypted transmission for tunnel construction
- **✍️ Rule Comments** - Clear commenting functionality, no need for additional memorization
- **💻 Intuitive MPTCP System Configuration** - Clear MPTCP interface display
- **🛜 Network Link Testing** - Test link latency, bandwidth, stability, and whether routing is detoured

- **📋 One-Click Export** - Package all files into a compressed archive for free migration (including comments and all information for complete migration)
- **📒 One-Click Import** - Recognize exported compressed packages for complete free migration
- **🔧 Intelligent Detection** - Automatic detection of system architecture, port conflicts, connection availability

- **📝 Intelligent Log Management** - Automatic log size limitation to prevent excessive disk usage
- **🗑️ Complete Uninstallation** - Phased comprehensive cleanup, "I leave gently, just as I came gently"
- **⚡ Full Native Realm Functionality** - Supports all native features of the latest realm version
- tcp/udp protocols
- ws/wss/tls encryption
- Single relay to multiple exits
- Multiple relays to single exit
- Proxy Protocol
- MPTCP
- Specify a specific entry IP for the relay server and a specific exit IP (suitable for multi-IP situations and one-entry-multiple-exits and multiple-entries-one-exit scenarios)
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

Continuously switches between exit servers in the rule group

- `IP Hash` mode (iphash)

Based on the hash value of the source IP, determines traffic direction, ensuring requests from the same IP always go to the same exit server

- Weight represents allocation probability

- Failover

When a certain exit is detected as failed, it's temporarily removed from the load balancing list. It will be automatically added back to the load balancing list after recovery

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

Clients can use the command `while ($true) { (Invoke-WebRequest -Uri 'http://ifconfig.me/ip' -UseBasicParsing).Content; Start-Sleep -Seconds 1 }` or `while true; do curl -s ifconfig.me; echo; sleep 1; done` to monitor IP changes in real-time and confirm mode effectiveness.

</details>

<details>
<summary>
<strong>Dual-Realm MPTCP System Integration</strong>
</summary>

MPTCP endpoints don't create a new virtual network interface, but rather:
Tell the MPTCP protocol stack: this IP address can be used for MPTCP connections
Specify paths: data can be transmitted through this IP address and corresponding network interface
Establish multiple paths: allow a single TCP connection to use multiple network paths simultaneously

**Q: Why specify both IP and network interface?**
Network interface: the system needs to know which physical network interface this IP address corresponds to for routing selection
IP address: the MPTCP protocol needs to know which IP addresses can be used to establish subflows
192.168.1.100 dev eth0 subflow fullmesh = tells MPTCP it can establish connections through this IP on eth0 interface
10.0.0.50 dev eth1 subflow fullmesh = tells MPTCP it can establish connections through this IP on eth1 interface

For more fine-grained control, consider:

Server-side signal endpoint configuration:
Fine-grained MPTCP control

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
| `iproute2` | MPTCP endpoint management | ✅ |

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
│   └── health/                  # Health check directory (failover)
│       └── health_status.conf   # Health status file
│
├── /etc/systemd/system/
│   ├── realm.service            # Main service file
│   ├── realm-health-check.service  # Health check service
│   └── realm-health-check.timer    # Health check timer
│
├── /etc/sysctl.d/
│   └── 90-enable-MPTCP.conf     # MPTCP system configuration file
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
- "https://ghfast.top/""https://ghproxy.gpnu.org/""https://gh.222322.xyz/" - Providing public accelerated sources
- All users who provided feedback and suggestions for the project

---

**⭐ If this project helps you, please give it a Star for support!**

[![Star History Chart](https://api.star-history.com/svg?repos=zywe03/realm-xwPF&type=Date)](https://www.star-history.com/#zywe03/realm-xwPF&Date)
