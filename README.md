<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Nexusyyan/bypax/main/assets/bypax-banner-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Nexusyyan/bypax/main/assets/bypax-banner-light.svg" />
    <img src="https://raw.githubusercontent.com/Nexusyyan/bypax/main/assets/bypax-banner-light.svg" alt="Bypax -- Cross-platform app routing and proxy workbench" width="100%" />
  </picture>
</p>

<p align="center">
  <strong>English</strong> | <a href="README.zh-CN.md">简体中文</a> | <a href="https://github.com/Nexusyyan/bypax/blob/main/DESIGN.md">Design System</a> | <a href="skills/bypax-agent/SKILL.md">Agent Skill</a>
</p>

<p align="center">
  <img alt="Release" src="https://img.shields.io/github/v/release/Nexusyyan/bypax?style=flat-square&color=0f172a&labelColor=f1f5f9" />
  <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Nexusyyan/bypax/ci.yml?style=flat-square&color=0f172a&labelColor=f1f5f9" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS-0f172a?style=flat-square&labelColor=f1f5f9" />
  <img alt="Stack" src="https://img.shields.io/badge/stack-Rust%20%2B%20Tauri%20v2-0f172a?style=flat-square&labelColor=f1f5f9" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-0f172a?style=flat-square&labelColor=f1f5f9" />
</p>

# Bypax

**Bypax** is an open-source cross-platform **app routing & proxy workbench** built with **Rust, Tauri v2, and React**, targeting the native **`sing-box v1.14+`** schema.

It combines a high-density node pool, plain-language split routing, full process-tree per-application proxying (Windows Zero-TUN WinDivert + macOS zero-cert `launchd` + `utun` path routing), transactional OS network recovery (**NetGuard**), multi-binary in-app self-updates, and a native **20-tool Stdio MCP Server & JSON CLI** for AI agents.

## Cross-Platform App Routing Architecture

| Capability | Windows (`Zero-TUN WinDivert`) | macOS (`Zero-Cert launchd + utun`) |
| :--- | :--- | :--- |
| **Interception Engine** | Dynamically loaded (`libloading`) signed `WinDivert.dll` + `WinDivert64.sys` (`SOCKET`/`FLOW`/`NETWORK`) + `smoltcp` userspace TCP/IP stack -> single loopback SOCKS5 mux (`127.0.0.1:10818`) with `auth_user` exit routing | Zero paid Apple certificate: `launchd` LaunchDaemon (`com.bypax.service`) + `sing-box` `utun` (`strict_route: false`) + `.app` bundle `process_path_regex` + trailing nested `invert: true` direct catch-all gate |
| **Routing Table & VPN Safety** | **Zero virtual NICs & zero OS route table edits** -- coexists seamlessly with corporate VPNs, WSL2, Docker Desktop, and Hyper-V | Unselected apps stay direct; automatic `route_exclude_address` bypass for RFC1918 LAN, OrbStack (`198.19.0.0/16`), Tailscale (`100.64.0.0/10`), and link-local IPv6 |
| **Child Process Tree** | Microsecond `NtQueryInformationProcess` ancestry + `CreateToolhelp32Snapshot` fallback captures deeply spawned IDE helpers (`language_server`, `node.exe`, `uv.exe`) | Bundle children captured natively by path regex; `libproc` + `sysctl` detects out-of-bundle children (e.g. `/opt/homebrew/bin/node`) for 1-click capture or ignore |
| **Privilege Isolation** | Non-elevated Medium Integrity GUI; privileged WinDivert/TUN isolated to GUI-bound ephemeral `bypax-service.exe worker-run` (`elevated_worker`, strict GUI PID binding via Win32 `WaitForSingleObject`, 0ms teardown on exit/crash, zero SCM background service; `bypax-cli service cleanup` removes legacy services) | Non-elevated GUI; privileged `utun` & NetGuard rollback isolated to `/Library/LaunchDaemons/com.bypax.service.plist` with GUI lease watchdog |
| **Connection Attribution** | PQ-TLS (`X25519MLKEM768`) SNI / HTTP / QUIC sniffing + `OriginRegistry` backfills real `Antigravity > node.exe` origins in Monitor with zero double-counting | Native `find_process` attribution with zero double-counting |

## Key Features

- **Orthogonal Takeover Mental Model**: Separate **Mode** from **Takeover** in a calm frameless TitleBar (`[Rule | Global | Direct] | [System Proxy] [Off | App Proxy | TUN]`) -- pairing an independent `System Proxy` switch with a mutually exclusive 3-way `Off | App Proxy | TUN` segmented control, synchronized in real time with the `304x456` System Tray Popover.
- **Per-App Routing (`Apps` View)**: 7 one-click presets (Antigravity, Cursor, VS Code, Git & SSH, Discord, Telegram, Steam) with 6-way outbound targeting (`Follow Routing`, `Main Exit`, `Auto Region`, `Specific Node`, `Direct`, `Reject`), drag-and-keyboard priority reordering, two-phase L4 process + L7 domain overrides, ancestor-tree process / `.app` picker, and a 3-step dry-run match tester.
- **High-Density Node Pool & Community Routing**: Import share URIs (`VLESS Reality/WS/gRPC/HTTPUpgrade`, `VMess`, `Trojan`, `Shadowsocks`, `Hysteria2`, `TUIC`, `AnyTLS`, `WireGuard`, `HTTP(S)`, `SOCKS5`), Base64 subscriptions, `sing-box` JSON, or Clash YAML; 0ms hot-switching; 33 official SagerNet + MetaCubeX GeoIP mirror `.srs` presets (including Steam CN CDN direct); Unified RTT latency engine; and dedicated visual DNS configuration.
- **Preflight Validation & NetGuard Crash Safety**: Every config swap runs `sing-box check -c` first; `NetGuard` snapshots OS proxy/DNS settings before mutation and restores them automatically on exit or crash (0ms teardown on Windows via GUI-bound `worker-run`; 15s lease watchdog on macOS `launchd`).
- **Native Self-Updater & Core Manager**: Proxy-aware GitHub Releases checker with `SHA256SUMS.txt` verification, multi-binary atomic replacement (cleanly stopping the active GUI-bound `worker-run` helper or macOS `launchd` daemon with `.prev` rollback), and automatic post-update state resume (`--resume-core`, `--resume-sys-proxy`, `--resume-app-proxy`, `--resume-tun`).
- **Studio Slate Bilingual UI**: Calm neutral Light (`#F6F7F9/#FFFFFF/#0F172A`) and Dark (`#0B1120/#0D1117/#161B22`) themes with zero external font/CDN requests, `@container` responsive tables down to `940x620`, and complete English / Simplified Chinese parity.

## Downloads & Installation

Pre-built Windows and macOS releases are published directly on [GitHub Releases](https://github.com/Nexusyyan/bypax/releases):

### Windows x64 (Windows 10/11)

- **Recommended Full Portable Bundle (`bypax-vX.Y.Z-x86_64-windows-portable.zip`)**: Extract and launch `bypax.exe` immediately. Bundles `bypax.exe`, `bypax-cli.exe`, `bypax-service.exe`, SHA-256 verified official unmodified `core/sing-box.exe`, SHA-256 & Authenticode verified `runtime/windivert/*` (zero sample tools), `skills/bypax-agent/SKILL.md`, `portable.json`, `LICENSE`, and `THIRD_PARTY_NOTICES.md`. All portable state stays in `./bypax-data/`.
- **Clean No-Driver Portable Bundle (`bypax-vX.Y.Z-x86_64-windows-nodriver.zip`)**: Same portable bundle without WinDivert driver binaries, paired with `scripts/fetch-windivert.ps1` for strict antivirus environments.
- **Standalone GUI Executable (`bypax-vX.Y.Z-x86_64-windows.exe`)**: Lightweight single-file GUI executable without bundled runtime binaries.

### macOS (Apple Silicon & Intel)

- **Apple Silicon (`bypax-vX.Y.Z-aarch64-macos.dmg`)** & **Intel (`bypax-vX.Y.Z-x86_64-macos.dmg`)**: Drag `Bypax.app` into `/Applications`. The app bundle embeds `bypax-cli`, `bypax-service`, official arch-matched `sing-box`, and `skills/bypax-agent/SKILL.md`.
- **First-Launch Quarantine Step (Zero-Cert Community Build)**: Because Bypax is ad-hoc signed without a paid Apple Developer certificate, clear the quarantine attribute once before opening:

```bash
xattr -dr com.apple.quarantine /Applications/Bypax.app
```

### Integrity Verification

Every release publishes a unified `SHA256SUMS.txt`. Verify your download before launching:

```powershell
# Windows (PowerShell)
Get-FileHash .\bypax-vX.Y.Z-x86_64-windows-portable.zip -Algorithm SHA256
```

```bash
# macOS
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

## AI Agent CLI & 20-Tool Stdio MCP Quickstart

Bypax ships a dedicated console binary (`bypax-cli`) exposing both a **20-tool Stdio MCP Server** (`protocolVersion: "2024-11-05"`, `serverInfo.name: "bypax-mcp"`) and structured JSON commands (`bypax-cli ctl --json`). When the GUI is open, mutations hot-sync over Plane 2 IPC (`bypax-ctl-v1`) in real time; when the GUI is closed, `bypax-cli` automatically falls back to SQLite WAL (`bypax.db`) for offline inspection, rule edits, and safe stop/cleanup (active core, System Proxy, App Proxy, and TUN remain strictly bound to the GUI lifecycle).

Add Bypax to Antigravity, Claude Code, or Cursor (or copy the auto-detected config from **Settings -> AI Agent Integration**):

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

On macOS, point `command` to `/Applications/Bypax.app/Contents/MacOS/bypax-cli`.

```powershell
# Structured JSON CLI examples
.\bypax-cli.exe ctl --json status
.\bypax-cli.exe ctl --json node list
.\bypax-cli.exe ctl --json app test --process Antigravity.exe --host api.github.com --port 443
.\bypax-cli.exe doctor
.\bypax-cli.exe ps
.\bypax-cli.exe service cleanup
.\bypax-cli.exe ctl schema
```

See [skills/bypax-agent/SKILL.md](skills/bypax-agent/SKILL.md) for the complete 20-tool reference and troubleshooting recipes.

## Workspace Architecture

```text
bypax/
├── crates/
│   ├── bypax-core/          # NodeIR, parsers, sing-box v1.14+ compiler, Control API, NetGuard, SQLite WAL, tester, supervisor, multi-binary updater
│   ├── bypax-appproxy/      # Cross-platform process-tree tracker, L4/L7 rule engine, PQ-TLS SNI sniffer, smoltcp netstack, OriginRegistry
│   ├── bypax-windivert/     # Windows dynamic libloading WinDivert driver wrapper (no-op stub on Unix)
│   ├── bypax-ipc/           # Dual-plane JSON-RPC IPC (Plane 1 privileged helper + Plane 2 user control)
│   ├── bypax-service/       # Privileged helper (Windows GUI-bound worker-run + legacy cleanup; macOS launchd)
│   └── bypax-cli/           # Console JSON CLI + 20-tool Stdio MCP Server (live IPC + offline WAL fallback)
├── src-tauri/               # Non-elevated Tauri v2 desktop host (com.bypax.desktop)
├── src/                     # React 19 + TypeScript + Tailwind v4 Studio Slate UI (en / zh-CN)
├── skills/bypax-agent/      # Bundled AI Agent SKILL.md
├── scripts/                 # Asset generator, fetch-core.ps1, fetch-windivert.ps1
└── DESIGN.md                # Canonical Studio Slate design system specification
```

## Development & Build from Source

### Prerequisites

- Rust stable (`rustc` + `cargo` + `clippy`)
- Node.js 22+ and `pnpm` 11+
- Windows 10/11 (WebView2 Runtime) or macOS 12+ (Xcode Command Line Tools)

### Commands

```powershell
# Optional: fetch verified official sing-box v1.14.4 and signed WinDivert 2.2.2-A locally
pwsh -NoProfile -File scripts/fetch-core.ps1
pwsh -NoProfile -File scripts/fetch-windivert.ps1

# Install dependencies and run full local quality gates
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Build release CLI, privileged service, and standalone Tauri GUI
cargo build --release -p bypax-cli -p bypax-service
pnpm tauri build --no-bundle
```

## Compliance & License

- **License**: Bypax is licensed under the [MIT License](LICENSE).
- **Clean Runtime Boundaries**: Bypax never links `libbox` or forks proxy core code -- it invokes official unmodified `sing-box v1.14+` binaries strictly out-of-process (GPL-3.0 Section 5 Mere Aggregation). On Windows, `WinDivert.dll` is loaded dynamically at runtime via `libloading` in compliance with LGPLv3 Section 4d. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for complete notices.
