<div align="center">

<img src="uu889_icon.png" width="88" alt="UU889 NetProbe"/>

# UU889 NetProbe · 网络测试工具

**一个零依赖、跨平台、单文件的桌面网络测试工具箱**

主机存活 · 端口扫描 · 路由追踪与地理定位 · 定时监控告警 · 网络诊断 · ARP 分析 · 离线 GeoIP

[![Website](https://img.shields.io/badge/官网-uu889.com-2ea44f)](https://uu889.com/)
[![Download](https://img.shields.io/badge/下载-Releases-1f6feb?logo=github&logoColor=white)](https://github.com/uu889/NetProbe/releases/latest)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)]()
[![Dependencies](https://img.shields.io/badge/依赖-仅标准库-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#许可证与致谢)

**🌐 官方网站：[uu889.com](https://uu889.com/)** ｜ [中文](README.md) · [English](README.en.md)

</div>

> **UU889** 把日常网络排障要用到的一堆小工具装进了一个 `net_probe.py` 里：既有开箱即用的**图形界面**，也有可脚本化的**命令行**。
> **纯 Python 标准库实现，无需 `pip install` 任何第三方包**，也能一键打包成免安装的 Windows `exe`。

---

## 目录

- [亮点](#亮点)
- [功能特性](#功能特性)
- [界面预览](#界面预览)
- [快速开始](#快速开始)
- [图形界面](#图形界面)
- [命令行用法](#命令行用法)
- [打包成 Windows exe（含自制图标）](#打包成-windows-exe含自制图标)
- [离线地理库](#离线地理库)
- [实现原理与技术要点](#实现原理与技术要点)
- [数据与配置文件位置](#数据与配置文件位置)
- [多语言](#多语言)
- [合规与免责声明](#合规与免责声明)
- [许可证与致谢](#许可证与致谢)

---

## 亮点

- 🧰 **一个文件搞定** —— 全部功能集中在单个 `net_probe.py`，拷贝即用，方便审计与分发。
- 🪶 **零第三方依赖** —— 只用 Python 标准库（含 Tkinter）；连离线 GeoIP 的 `.mmdb` 读取器都是自己用标准库写的。
- 🖥️ **图形界面 + 命令行双模** —— 同一份代码，既能点鼠标，也能 `--json` 接入脚本/CI。
- 🌍 **跨平台** —— Windows / macOS / Linux，自动适配各系统的 `ping` / `tracert` / `traceroute` / `arp`。
- 🔒 **合规优先** —— 内置授权白名单 + 操作审计；**不做弱口令爆破**，仅对暴露的高危服务做防御性标注。
- 📦 **一键打包 exe** —— 附带自制原创「U」图标（纯代码生成，无版权风险），目标机无需装 Python。

---

## 功能特性

| 模块 | 能力 |
|---|---|
| **主机存活扫描** | 对 IP 段批量 Ping（真 ICMP，免 root），显示 RTT / TTL、并发可调 |
| **端口扫描** | TCP connect 扫描 + UDP 协议探针；服务识别、Banner 抓取、**高危端口红底标注**；`selectors` 高速引擎；有 root 时走**原始套接字 SYN 半开**（无 root 自动回退） |
| **路由追踪 + 地理定位** | 逐跳 traceroute，每跳附国家/地区/城市与 ISP/Org/AS；**Leaflet 世界地图**可视化；地理库支持**在线或一键下载离线库** |
| **定时监控 + 变更告警** | 周期扫描主机存活/端口开放，变更即告警；多目标多行输入、支持 `目标:端口` 混填；**邮件 / Webhook（Slack、Discord、钉钉、企业微信、飞书）**；SQLite 入库、HTML 报表 + 趋势图、PDF 导出、多设备汇总看板 |
| **网络诊断** | DNS 正/反向解析、HTTP(S) 检查、TLS 证书检查、Ping 质量（丢包/抖动）、路径 MTU、IP 归属地；全面支持 **IPv6** |
| **链路质量曲线** | 对目标持续测量并绘制丢包/时延曲线（内联 SVG，离线可看） |
| **ARP 监听** | 读取/主动填充本机 ARP 邻居表（IP↔MAC + 厂商识别），持续监控发现**新设备/ MAC 变化（疑似 ARP 欺骗）**；**双击某 IP 可监听其广播/组播报文**（NetBIOS/mDNS/SSDP/LLMNR/DHCP…） |
| **IP 归属地** | 域名 → 全部 IPv4+IPv6、rDNS 反查、国家/地区/城市、ISP/Org/AS，表格展示可导出 |
| **密码生成** | `secrets` 密码学安全随机，长度/字符集可选，附强度评估 |
| **HTTP API / Web 面板** | `serve` 子命令常驻，提供 JSON API + 简易网页面板，便于集成 |

---

## 界面预览

<div align="center">

| 主机存活扫描 | 端口扫描 |
|:--:|:--:|
| ![主机存活扫描](docs/host_live_scan.jpg) | ![端口扫描](docs/portscan.jpg) |
| **路由追踪 + 地理定位** | **定时监控 + 变更告警** |
| ![路由追踪](docs/tracert_geo.jpg) | ![定时监控](docs/monitor_changing_alerts.jpg) |
| **网络诊断** | **链路质量曲线** |
| ![网络诊断](docs/network_test.jpg) | ![链路质量曲线](docs/link_test.jpg) |
| **ARP 监听** | **IP 归属地** |
| ![ARP 监听](docs/arp.jpg) | ![IP 归属地](docs/ip_geo.jpg) |
| **密码生成** | |
| ![密码生成](docs/password.jpg) | |

</div>

---

## 快速开始

**普通用户（Windows）**：直接到 **[Releases 页面](https://github.com/uu889/NetProbe/releases/latest)** 下载 `UU889-NetProbe.exe`，双击即用，**无需安装 Python**。

**从源码运行 / 开发**：需 Python **3.8+**（Windows / macOS 官方安装包自带 Tkinter）。
> Linux 若无 Tkinter：`sudo apt install python3-tk`（Debian/Ubuntu）或 `sudo yum install python3-tkinter`（CentOS/RHEL）。

```bash
# 克隆或直接下载 net_probe.py 到本地
git clone https://github.com/uu889/NetProbe.git
cd NetProbe

# 启动图形界面（双击 net_probe.py 也可以）
python net_probe.py

# 或直接用命令行，例如扫一个网段的存活主机
python net_probe.py ping 192.168.1.0/24
```

无需 `pip install`，无需虚拟环境。

---

## 图形界面

启动后是一个多标签窗口，顶部可切换**界面语言**、打开**数据目录**：

```
主机存活扫描 │ 端口扫描 │ 路由追踪 + 地理定位 │ 定时监控 + 变更告警 │ 网络诊断
链路质量曲线 │ ARP 监听 │ IP归属地 │ 密码生成
```

- **端口扫描**：默认勾选「只显示开放端口 / 抓取 Banner / 高速模式 / 服务识别」；开放的高危端口（RDP/SMB/Redis/数据库/Docker API 等）会红底标注并附风险说明。
- **路由追踪**：勾选「查询每跳地理位置」后逐跳定位；点「🌍 世界地图」在浏览器打开可视化路径；地理库可切换在线/离线。
- **定时监控**：目标框为多行文本，可放大；**每行 `目标:端口` 就监听该端口，否则用「端口」框的端口**——只要有一行是 `目标:端口` 就自动按端口监控。
- **ARP 监听**：双击列表里的任意 IP，弹窗实时监听它发出的广播/组播报文。

> 💡 想在 README 里放截图，把图片放到 `docs/` 目录并在此处插入即可，例如：
> `![端口扫描](docs/port-scan.png)`

---

## 命令行用法

所有子命令都支持 `--json` 输出，便于脚本处理。

```bash
python net_probe.py ping 192.168.1.0/24                 # IP 段存活扫描
python net_probe.py scan 10.0.0.1 --ports 1-1024        # 端口扫描 (TCP/UDP)
python net_probe.py trace 8.8.8.8                        # 路由追踪 + 地理定位
python net_probe.py dns example.com                      # DNS 正/反向解析
python net_probe.py http https://example.com             # HTTP(S) 检查
python net_probe.py tls example.com --port 443           # TLS 证书检查
python net_probe.py quality 8.8.8.8 --count 10           # 丢包/抖动
python net_probe.py mtu 8.8.8.8                          # 路径 MTU 探测
python net_probe.py ipinfo github.com                    # IP 归属地(多IP/rDNS/ISP)
python net_probe.py arp                                  # 本地 ARP 邻居表
python net_probe.py genpass --length 20 --count 5        # 生成随机密码
python net_probe.py serve --port 8899                    # 常驻 HTTP JSON API + 面板
python net_probe.py genicon --out uu889.ico              # 生成 U 图标(打包 exe 用)
python net_probe.py geodl                                # 下载离线地理库(DB-IP)
python net_probe.py --gui                                # 强制打开图形界面
```

> `scan` 的 `--syn` 走原始套接字 SYN 半开扫描，需要管理员/root；否则自动回退到高速 connect 扫描。

---

## 打包成 Windows exe（含自制图标）

> 已在 **Windows 11 + Python 3.14.6** 环境下打包验证通过。安装 Python 时请勾选 *Add Python to PATH*。

```bat
:: 1) 安装 PyInstaller
pip install pyinstaller

:: 2) 生成自制 U 图标（无需先运行 GUI）
python net_probe.py genicon --out uu889.ico

:: 3) 三选一进行打包：

:: (A) 自用图标 + 无控制台窗口
pyinstaller --onefile --windowed --icon uu889.ico --name UU889-NetProbe net_probe.py

:: (B) GUI，无黑框，【推荐】
pyinstaller --onefile --noconsole --name UU889-NetProbe net_probe.py

:: (C) 保留控制台，CLI 可用
pyinstaller --onefile --name UU889-NetProbe-cli net_probe.py
```

产物在 `dist\` 目录，双击即用，**目标机无需安装 Python**；用 `--icon uu889.ico` 时图标为自制「U」标（**不是** PyInstaller 默认图标）。

- 🪶 **零依赖**：PyInstaller 会自动打包 Python 运行时与 Tkinter；`ping`/`tracert` 用系统自带命令，无需额外配置。
- 🖼 **图标缓存**：重打包后若资源管理器仍显示旧图标，是 Windows 图标缓存所致——换个 exe 文件名，或执行 `ie4uinit.exe -show`（或删 `%LocalAppData%\IconCache.db` 后重启资源管理器）即可刷新。
- 🛡 **杀软 / SmartScreen**：未签名的「网络扫描」类单文件 exe 容易被误报或触发 SmartScreen「未知发布者」提示，这是通病；可对 exe 做**代码签名**或在内网加白名单解决。

> 也可用 **Nuitka**：`python -m nuitka --onefile --windows-console-mode=disable --enable-plugin=tk-inter net_probe.py`，启动更快、体积有时更小。

---

## 离线地理库

路由追踪/IP 归属地的地理定位，默认走在线接口 `ip-api.com`（免费额度约 45 次/分钟）。如需**离线、无限速、不外泄查询目标**：

1. 在「路由追踪」页勾选 **「下载到本地并离线使用(不联网)」**，点 **「下载/更新离线库」**；
2. 或命令行 `python net_probe.py geodl`。

- 下载的是 **DB-IP City Lite**（免费、**CC BY 4.0 可自由再分发**，含 IPv4+IPv6；约 60 MB 下载 / 130 MB 硬盘），存到数据目录 `geo/dbip-city-lite.mmdb`。
- 读取器是**纯标准库自研的 MMDB 解析器**（`mmap` 内存映射，兼容 DB-IP / MaxMind GeoLite2 的 `.mmdb`），**无需第三方 `geoip2`**，打包 exe 也能直接用。
- 离线库提供**国家/地区/城市**；ISP/AS 仍由在线接口提供。

---

## 实现原理与技术要点

- **Ping / Traceroute**：调用系统命令并解析输出，跨平台自动适配；Ping RTT 解析不依赖本地化词（兼容中文 Windows）。
- **TCP 扫描**：标准 `connect_ex`，`open`=握手成功 / `closed`=被拒 / `filtered`=超时；`selectors` 非阻塞高并发引擎大幅提速。
- **UDP 扫描**：对 DNS/NTP/SNMP/NetBIOS/RPC/IKE/IPMI/MSSQL/SSDP/SIP/mDNS 等发**协议探针**，**只有收到应答才判为 `open`**；无响应记为 `open|filtered`（未知，不计为开放），并给出 `确认开放 / 无响应 / 关闭` 的诚实统计。
  > ⚠️ WireGuard 等加密 VPN 会**静默丢弃未授权数据包**，任何外部扫描器（含 nmap）都无法确认其端口开放——这是其设计，不是本工具缺陷。
- **SYN 半开**：原始套接字发 SYN、嗅探 SYN-ACK/RST，需 root；已在 Linux user+net 命名空间下做过端到端验证，结果与 connect 扫描一致。
- **离线 GeoIP**：纯标准库实现 MaxMind DB 二进制格式（搜索树 + 数据段解码器），支持 24/28/32 位记录与 IPv4-in-IPv6 树。
- **线程安全 GUI**：后台线程 + `queue.Queue` + `root.after` 轮询，界面不卡死。
- **告警渠道**：Webhook 按平台自动组织报文；邮件走 `smtplib`（SSL/STARTTLS）。
- **持久化**：`sqlite3` 存监控事件，报表/趋势图用内联 SVG 绘制，离线可看。

---

## 数据与配置文件位置

统一存放在系统用户数据目录，避免 exe 运行时「找不到数据库」：

| 系统 | 目录 |
|---|---|
| Windows | `%APPDATA%\UU889` |
| macOS / Linux | `~/.config/UU889` |

其中包含：监控事件库 `netprobe.db`、配置 `netprobe_config.json`、变更日志 `netprobe_monitor_log.csv`、操作审计 `netprobe_audit.log`、离线地理库 `geo/`、语言包 `lang/`、图标 `uu889.ico`。

> ⚠️ SMTP 密码以明文存于本地 `netprobe_config.json`，请注意文件权限，并建议使用邮箱「应用专用密码/授权码」。

---

## 多语言

- 界面顶部下拉可切换语言，内置 **中文 / English / Français / Español / Português**。
- ⚠️ **切换语言后需重启程序生效**（重启后按新语言加载界面）。
- 外部语言包放 `<数据目录>/lang/*.json`，格式：
  ```json
  { "language": "de", "strings": { "开始扫描": "Scan starten", "停止": "Stopp" } }
  ```
- 未翻译的词自动回退中文；新增/修改后重启生效。

---

## 合规与免责声明

- **仅限对你拥有或已获明确授权的网络与主机进行测试。** 大范围扫描可能触发对方安全告警，甚至违反当地法律法规。
- 工具内置**授权白名单**（按 CIDR 校验目标，越权拦截）与**操作审计日志**。
- 本工具**刻意不实现弱口令爆破/暴力破解**等攻击性功能，仅对暴露的高危端口做**防御性风险标注**，帮助你发现并加固自己的资产。
- 使用本工具造成的一切后果由使用者自行承担，作者不承担任何责任。

---

## 许可证与致谢

- **许可证**：建议以 [MIT License](https://opensource.org/license/mit) 发布（在仓库根目录放一个 `LICENSE` 文件即可）。你也可以按需更换。
- **IP 地理数据**：离线库使用 [DB-IP.com](https://db-ip.com) 的 **IP to City Lite** 数据库，依据 **[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)** 授权——分发含该数据的构建时，请保留对 DB-IP 的署名。
- **在线定位**：由 [ip-api.com](https://ip-api.com) 提供免费接口。
- **地图**：世界地图基于 [Leaflet](https://leafletjs.com) + [OpenStreetMap](https://www.openstreetmap.org)。

---

<div align="center">

如果这个项目对你有帮助，欢迎点个 ⭐ Star！

</div>
