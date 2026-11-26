# Bypax -- Repository Agent Guide

Cross-platform app routing and proxy workbench built with Rust, Tauri v2, and React for the native `sing-box` v1.14+ schema.

## Stack & Workspace Layout

- **Stack**: Rust + Tauri v2 + React 19 + TypeScript + Tailwind CSS v4 + `pnpm` (single root Cargo Workspace)
- **Key paths**:
  - `crates/bypax-core/` -- Core domain models, URI/Base64/JSON/YAML parsers, `sing-box` v1.14+ reachability tree-shaking compiler (Windows `app-proxy-in` loopback mux + macOS `utun` `.app` path routing), Clash API control client, isolated batch latency tester, NetGuard proxy/DNS snapshot manager, SQLite WAL storage (`bypax.db` + `app_proxy_rules`), `.srs` rule cache, core downloader, process supervisor, and multi-binary self-updater (`updater.rs`)
  - `crates/bypax-appproxy/` -- Cross-platform per-app routing engine: process-tree tracker (Windows `NtQueryInformationProcess` + `CreateToolhelp32Snapshot`, macOS `libproc` + `sysctl`), 7 built-in presets, two-phase L4/L7 rule engine, PQ-TLS SNI / HTTP / QUIC sniffer, `smoltcp` userspace netstack, UDP relay, dry-run tester, and `OriginRegistry` connection attribution
  - `crates/bypax-windivert/` -- Windows runtime dynamic `libloading` loader for signed `WinDivert.dll` + `WinDivert64.sys` (`SOCKET`/`FLOW`/`NETWORK` capture; compiles as no-op stub on Unix)
  - `crates/bypax-ipc/` -- Dual-plane typed JSON-RPC IPC protocol: Plane 1 privileged service (`\\.\pipe\bypax-svc-v1` with SDDL / `/var/run/bypax-svc.sock` + `BYPAX_IPC_TOKEN`) and Plane 2 user control (`\\.\pipe\bypax-ctl-v1` / `<runtime_dir>/bypax-ctl.sock` `0600`)
  - `crates/bypax-service/` -- Privileged daemon (`BypaxService` Windows Service + on-demand UAC `worker-run` + macOS `launchd` `com.bypax.service`) enforcing mutual exclusion between App Proxy and Global TUN, 15s GUI heartbeat watchdog, and NetGuard rollback
  - `crates/bypax-cli/` -- Standalone console CLI (`bypax-cli ctl --json`, `doctor`, `ps`, `service`) and zero-SDK 20-tool Stdio MCP Server (`bypax-cli mcp`, `protocolVersion: "2024-11-05"`, `serverInfo.name = "bypax-mcp"`) with live Plane 2 IPC and automatic offline SQLite WAL fallback
  - `src-tauri/` -- Non-elevated Tauri v2 desktop host (`bypax` / `com.bypax.desktop`), tray popover, single-instance guard, Plane 2 control server, and IPC commands
  - `src/` -- React + TypeScript bilingual UI (`src/locales/{en,zh-CN}.json`, 7 views: `Nodes`, `Apps`, `Routing`, `DNS`, `Monitor`, `Core`, `Settings`)
  - `DESIGN.md` -- Canonical **Studio Slate** UI design system (`#F6F7F9/#FFFFFF/#0F172A` Light, `#0B1120/#0D1117/#161B22` Dark) and Rainbow Overpass X brand specification
  - `skills/bypax-agent/SKILL.md` -- Bundled AI Agent skill guide for Antigravity, Claude Code, and Cursor
  - `scripts/` -- `generate-bypax-assets.mjs`, `fetch-core.ps1`, `fetch-windivert.ps1`
  - `.github/workflows/{ci,release}.yml` -- Automated cross-platform CI (`windows-latest`, `macos-latest`, `ubuntu-latest`) and idempotent Release matrix

## Verification Commands

```powershell
# 1. Pure 7-bit ASCII source check (zero non-ASCII bytes in source/scripts/workflows)
node "$env:USERPROFILE\.agents\skills\project-pipeline\scripts\check_ascii.mjs" --root "."

# 2. Frontend typecheck, unit tests, and production bundle
pnpm typecheck
pnpm test
pnpm build

# 3. Rust workspace lint (deny warnings) and full tests
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# 4. Release binaries (CLI, privileged service, and standalone Tauri GUI)
cargo build --release -p bypax-cli -p bypax-service
pnpm tauri build --no-bundle
```

## Project-Specific Constraints

- Keep all `*.rs`, `*.ts`, `*.tsx`, `*.js`, `*.jsx`, `*.mjs`, `*.py`, `*.ps1`, `*.yml`, and `*.yaml` files 100% pure 7-bit ASCII English; place Simplified Chinese UI copy exclusively in `src/locales/zh-CN.json` (and Chinese docs in `README.zh-CN.md`).
- Follow `DESIGN.md` (**Studio Slate**) strictly: Light `#F6F7F9/#FFFFFF/#0F172A`, Dark `#0B1120/#0D1117/#161B22` with mandatory dark canvas hairline border, zero external font/CDN origins, rainbow colors isolated solely to `src/components/BrandLogo.tsx`, and `@container` responsive tables with zero fixed `min-width`.
- Never include `sing-box` in product names, repository names, crate names, or bundle identifiers (`com.bypax.desktop`).
- Never link `libbox` or copy `hiddify-app` code; invoke only unmodified external official `sing-box` v1.14+ binaries out-of-process with SHA-256 verification.
- Never statically link `WinDivert.dll`; load dynamically via `libloading` at runtime and preserve LGPLv3 Section 4d user-replaceability.
- Describe macOS App Proxy accurately as **zero-cert `launchd` + `utun` path routing** (zero paid Apple Developer certificate; never claim Apple System Extension APIs).
- Always run `sing-box check -c` preflight validation before swapping active runtime configs, and always snapshot OS proxy/DNS settings via `NetGuard` before mutating network state.
- Keep the Windows GUI strictly non-elevated (Medium Integrity); isolate privileged WinDivert and TUN operations to `bypax-service`.
- Keep `.gitignore` runtime ignores anchored with leading slashes (`/core/`, `/runtime/windivert/`, `/bypax-data/`, `/target/`, `/node_modules/`, `/dist/`) so source files such as `src/features/core/CoreView.tsx` are always tracked.
- Ensure `src/locales/en.json` and `src/locales/zh-CN.json` always maintain exact key parity.
