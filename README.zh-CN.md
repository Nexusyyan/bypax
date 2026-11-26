<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/bypax-banner-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="assets/bypax-banner-light.svg" />
    <img src="assets/bypax-banner-light.svg" alt="Bypax -- 跨平台应用分流与代理工作台" width="100%" />
  </picture>
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>简体中文</strong> | <a href="DESIGN.md">设计规范 (DESIGN.md)</a> | <a href="skills/bypax-agent/SKILL.md">Agent 技能指南</a>
</p>

<p align="center">
  <img alt="Release" src="https://img.shields.io/github/v/release/Nexusyyan/bypax?style=flat-square&color=0f172a&labelColor=f1f5f9" />
  <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Nexusyyan/bypax/ci.yml?style=flat-square&color=0f172a&labelColor=f1f5f9" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS-0f172a?style=flat-square&labelColor=f1f5f9" />
  <img alt="Stack" src="https://img.shields.io/badge/stack-Rust%20%2B%20Tauri%20v2-0f172a?style=flat-square&labelColor=f1f5f9" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-0f172a?style=flat-square&labelColor=f1f5f9" />
</p>

# Bypax

**Bypax** 是一款基于 **Rust + Tauri v2 + React** 打造的开源跨平台**应用分流与代理工作台**，面向纯净的 **`sing-box v1.14+`** 原生 Schema。

它将高密度节点池管理、零术语社区分流策略、进程树级应用透明代理（Windows 零 TUN WinDivert + macOS 零证书 `launchd` + `utun` 路径分流）、事务化防断网保护（**NetGuard**）、多二进制应用内自更新以及原生 **20 工具 Stdio MCP Server 与 JSON CLI** 融合于一体。

## Windows 与 macOS 双平台应用代理架构对比

| 维度 | Windows（**零 TUN WinDivert 引擎**） | macOS（**零证书 `launchd` + `utun` 路径分流**） |
| :--- | :--- | :--- |
| **流量接管原理** | 运行时通过 `libloading` 动态加载官方签名 `WinDivert.dll` + `WinDivert64.sys`（`SOCKET`/`FLOW`/`NETWORK`），经 `smoltcp` 用户态协议栈单端口回环复用至 `127.0.0.1:10818`（`auth_user` 按规则精准路由） | 无需付费 Apple 证书：由 `/Library/LaunchDaemons/com.bypax.service.plist` 拉起 `bypax-service`，编译 `sing-box` `utun`（`strict_route: false`）+ `.app` 路径正则 `process_path_regex` + 尾部嵌套 `invert: true` 直连门控 |
| **路由表与 VPN 兼容性** | **零虚拟网卡、零系统路由表改动**，与企业 VPN、WSL2、Docker Desktop、Hyper-V 无缝共存 | 未选中应用自动直连；默认通过 `route_exclude_address` 绕过 RFC1918 内网、OrbStack（`198.19.0.0/16`）、Tailscale（`100.64.0.0/10`）与 IPv6 链路本地网段 |
| **派生子进程树捕获** | `NtQueryInformationProcess` 微秒级祖先链解析 + `CreateToolhelp32Snapshot` 兜底，自动捕获 IDE 派生的深层 `language_server`、`node.exe`、`uv.exe` 等子进程 | `.app` 包内子进程由路径正则原生覆盖；`libproc` + `sysctl` 实时探测包外派生子进程（如 `/opt/homebrew/bin/node`）并提供一键纳入或忽略 |
| **权限隔离与防断网** | 桌面 GUI 始终保持非提权标准用户运行；WinDivert 与全局 TUN 特权集中于 `BypaxService`（常驻后台服务）或按需 UAC 临时进程，配 15 秒 GUI 心跳看门狗 | 桌面 GUI 非提权运行；`utun` 启停与 NetGuard 代理/DNS 回滚由 `com.bypax.service` 守护进程托管 |
| **监控归因与零双计** | 跨分段后量子 TLS（`X25519MLKEM768`）SNI / HTTP / QUIC 嗅探 + `OriginRegistry` 原地回填 `Antigravity > node.exe` 真实来源，杜绝流量双计 | `sing-box` 原生 `find_process` 直接归因进程名与路径，天然零双计 |

## 核心特性

- **清晰正交的「模式 + 接管」控制模型**：将 **分流模式**（`规则 | 全局 | 直连`）与 **流量接管**（独立 `系统代理` 开关 + 三选一互斥分段 `捕获：关闭 | 应用 | TUN`）彻底解耦，并在顶部无边框标题栏与 `304x456` 自定义系统托盘浮层间实时联动。
- **进程树级应用代理（`Apps` 视图）**：内置 7 大开发与常用预设（Antigravity、Cursor、VS Code、Git & SSH、Discord、Telegram、Steam），每条规则支持 6 种出口策略（跟随分流 / 主出口 / 地区优选 / 指定节点 / 直连 / 拦截）、拖拽与快捷键调序、L4 进程 + L7 域名双阶段覆写、带祖先树的进程 / `.app` 选择器以及三步轨迹干跑测试抽屉。
- **高密度虚拟滚动节点池与经典社区分流**：支持导入 `VLESS (Reality/WS/gRPC/HTTPUpgrade)`、`VMess`、`Trojan`、`Shadowsocks`、`Hysteria2`、`TUIC`、`AnyTLS`、`WireGuard`、`HTTP(S)`、`SOCKS5` 分享链接、Base64 订阅、`sing-box` JSON 与 Clash YAML；0ms 热切主出口；内置 32 项官方 SagerNet `.srs` 规则预设、Unified RTT 剥离握手测速引擎与独立可视化 DNS 配置页。
- **配置预检与 NetGuard 崩溃自愈**：每次切换配置前必经 `sing-box check -c` 校验；任何系统代理或 DNS 变更均先落盘 `NetGuard` 快照，GUI 异常退出后 15 秒内自动停止接管并还原网络环境。
- **多二进制原生自更新与内核管理**：代理感知的 GitHub Releases 版本检查与 `SHA256SUMS.txt` 强制校验，支持多二进制原子替换（自动协调 `BypaxService` 优雅停启、`.prev` 整批失败回滚与用户 `bypax-data/` 完整保护），重启后无缝恢复运行状态。
- **Studio Slate 冷静现代双语界面**：专为高频桌面工具打造的浅色（`#F6F7F9/#FFFFFF/#0F172A`）与深色（`#0B1120/#0D1117/#161B22`）双主题，零外部字体与 CDN 请求，`@container` 容器查询响应式表格在 `940x620` 最小窗口下零横向溢出，中英双语键 100% 对齐。

## 下载安装

所有预编译版本均由 GitHub Actions 从源码透明构建并发布于 [GitHub Releases](https://github.com/Nexusyyan/bypax/releases)：

### Windows x64（Windows 10 / 11）

- **推荐完整便携包（`bypax-vX.Y.Z-x86_64-windows-portable.zip`）**：解压即可双击 `bypax.exe` 使用。内含 `bypax.exe`、`bypax-cli.exe`、`bypax-service.exe`、经 SHA-256 校验的官方未修改 `core/sing-box.exe`、经 SHA-256 与 Authenticode 验签的 `runtime/windivert/*`（零 sample 工具）、`skills/bypax-agent/SKILL.md`、`portable.json` 与合规许可；所有数据保存在 `./bypax-data/`。
- **纯净无驱动便携包（`bypax-vX.Y.Z-x86_64-windows-nodriver.zip`）**：适合严苛杀毒软件环境，不含驱动文件，附带 `scripts/fetch-windivert.ps1` 按需拉取校验官方驱动。
- **轻量单文件 GUI（`bypax-vX.Y.Z-x86_64-windows.exe`）**：仅包含桌面 GUI 可执行程序。

### macOS（Apple Silicon 与 Intel）

- **Apple Silicon（`bypax-vX.Y.Z-aarch64-macos.dmg`）** 与 **Intel（`bypax-vX.Y.Z-x86_64-macos.dmg`）**：将 `Bypax.app` 拖入 `/Applications` 即可。应用包内已一并集成 `bypax-cli`、`bypax-service`、对应架构的官方未修改 `sing-box` 以及 `skills/bypax-agent/SKILL.md`。
- **首次启动解除隔离说明（零付费证书社区签名版）**：由于社区开源版本采用 ad-hoc 签名而未使用付费 Apple 开发者证书，首次启动前请执行一次以下命令解除 Gatekeeper 隔离标记：

```bash
xattr -dr com.apple.quarantine /Applications/Bypax.app
```

### 完整性校验

每次发版均附带统一的 `SHA256SUMS.txt` 文件，下载后可核对校验和：

```powershell
# Windows (PowerShell)
Get-FileHash .\bypax-v0.1.0-x86_64-windows-portable.zip -Algorithm SHA256
```

```bash
# macOS
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

## AI Agent CLI 与 20 工具 Stdio MCP 快速接入

Bypax 随包提供独立控制台程序 `bypax-cli`，同时支持 **20 工具原生 Stdio MCP Server**（`protocolVersion: "2024-11-05"`，`serverInfo.name: "bypax-mcp"`）与结构化 JSON 命令行（`bypax-cli ctl --json`）。桌面端运行时通过 Plane 2 控制通道 0ms 实时热同步 UI；桌面端未启动时自动回退读写 SQLite WAL（`bypax.db`）并直连特权服务通道。

将以下配置加入 Antigravity、Claude Code 或 Cursor（亦可在界面 **设置 -> AI 助手集成** 中一键复制含本机绝对路径的配置）：

```json
{
  "mcpServers": {
    "bypax": {
      "command": "C:\\path\\to\\bypax\\bypax-cli.exe",
      "args": ["mcp"]
    }
  }
}
```

在 macOS 上请将 `command` 指向 `/Applications/Bypax.app/Contents/MacOS/bypax-cli`。

```powershell
# 结构化 JSON 命令行示例
.\bypax-cli.exe ctl --json status
.\bypax-cli.exe ctl --json nodes
.\bypax-cli.exe ctl --json app test --process Antigravity.exe --host api.github.com --port 443
.\bypax-cli.exe doctor
.\bypax-cli.exe ps
.\bypax-cli.exe ctl schema
```

完整 20 项工具定义与排障范式请参阅 [skills/bypax-agent/SKILL.md](skills/bypax-agent/SKILL.md)。

## 本地开发与源码编译

### 环境要求

- Rust stable（`rustc` + `cargo` + `clippy`）
- Node.js 22+ 与 `pnpm` 11+
- Windows 10/11（WebView2 Runtime）或 macOS 12+（Xcode Command Line Tools）

### 常用命令

```powershell
# 可选：在本地拉取并校验官方 sing-box v1.14.4 与签名版 WinDivert 2.2.2-A
pwsh -NoProfile -File scripts/fetch-core.ps1
pwsh -NoProfile -File scripts/fetch-windivert.ps1

# 安装依赖并运行完整质量门禁
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# 编译 Release CLI、特权服务与独立便携 GUI
cargo build --release -p bypax-cli -p bypax-service
pnpm tauri build --no-bundle
```

## 开源协议与合规说明

- **协议**：Bypax 主仓库采用 [MIT License](LICENSE) 开源。
- **干净的运行时合规边界**：Bypax 绝不静态或动态链接 `libbox`，亦不维护代理内核源码 Fork；所有官方未修改 `sing-box v1.14+` 二进制均以独立外部进程方式调用（符合 GPL-3.0 第 5 节 Mere Aggregation）。Windows 端 `WinDivert.dll` 仅在运行时经 `libloading` 动态加载，用户可按 LGPLv3 第 4d 条自由替换驱动。完整声明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
