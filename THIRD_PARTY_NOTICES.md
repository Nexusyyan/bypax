# Third-Party Notices

Bypax itself is licensed under the MIT License (see `LICENSE`).

Bypax keeps strict license boundaries with external runtimes and drivers: it invokes unmodified proxy core executables strictly out-of-process, and dynamically loads optional Windows packet-interception libraries at runtime without static linking.

## External Runtime Components

### 1. sing-box (Out-of-Process Mere Aggregation)
- **Project**: https://github.com/SagerNet/sing-box
- **License**: GNU General Public License v3.0 or later (`GPL-3.0-or-later`) with `name-use-assertion`
- **Corresponding Source**: Unmodified upstream source code for the exact release version (`v1.14.4` and newer) is publicly available at https://github.com/SagerNet/sing-box/releases.
- **Usage**: Invoked strictly as an unmodified standalone external executable (`core/sing-box.exe` on Windows; `core/sing-box` on macOS/Linux) via out-of-process CLI execution (`sing-box check -c` / `sing-box run -c`). Bypax does **not** link `libbox` or copy proxy core source code. Portable release archives and macOS DMG bundles aggregate the unmodified official executable alongside Bypax as a separate file under GPL-3.0 Section 5 (Mere Aggregation) so first-time users in restricted networks can run immediately. Bypax is an independent third-party desktop client and is not affiliated with or endorsed by the SagerNet project.

### 2. WinDivert (Windows Runtime Dynamic Dependency)
- **Project**: WinDivert (Windows Packet Divert) -- https://github.com/basil00/WinDivert
- **Copyright**: Copyright (C) basil00 / reqrypt.org
- **License**: GNU Lesser General Public License v3.0 (`LGPL-3.0`) or GNU General Public License v2.0 (`GPL-2.0`)
- **Official Source & Releases**: https://github.com/basil00/WinDivert/releases
- **Usage & LGPLv3 Section 4d Compliance**: On Windows, Bypax dynamically loads `WinDivert.dll` at runtime via `libloading` (`LoadLibrary`) and communicates with the official Authenticode-signed `WinDivert64.sys` driver (`2.2.2-A`, SHA-256 verified). Because `WinDivert.dll` is never statically linked into any Bypax binary, users may freely replace `WinDivert.dll` and `WinDivert64.sys` inside `runtime/windivert/` with any compatible or modified build in accordance with LGPLv3 Section 4d. Full Windows portable archives ship only `WinDivert.dll`, `WinDivert64.sys`, `WINDIVERT_LICENSE.txt`, and `WINDIVERT_README.txt` (zero sample tools); a clean `-nodriver.zip` archive is also published alongside `scripts/fetch-windivert.ps1`.

### 3. Wintun (Optional Windows Global TUN Mode)
- **Project**: https://www.wintun.net/
- **License**: GNU General Public License v2.0 (`GPL-2.0-only`) with Prebuilt Binaries Exception
- **Usage**: When Global TUN mode is enabled on Windows, the official signed `wintun.dll` is managed by the external runtime / privileged service without static linking into Bypax.

### 4. SagerNet Rule-Sets (`sing-geosite` / `sing-geoip`)
- **Projects**:
  - https://github.com/SagerNet/sing-geosite
  - https://github.com/SagerNet/sing-geoip
- **License**: Derived from community domain/IP rule databases (including v2fly `domain-list-community`, MIT License, and upstream rule-set repositories).
- **Usage**: Downloaded and cached externally as binary `.srs` data files at runtime; never compiled into Bypax source or binaries.

## Notable Open-Source Libraries

### 5. smoltcp
- **Project**: https://github.com/smoltcp-rs/smoltcp
- **License**: Zero-Clause BSD (`0BSD`)
- **Usage**: Userspace TCP/IP network stack used inside `bypax-appproxy` to reconstruct intercepted Windows application flows without creating a virtual TUN adapter.

### 6. Lucide (`lucide-react`)
- **Project**: https://lucide.dev/
- **License**: ISC License (`ISC`)
- **Usage**: Monochrome stroke iconography across the desktop UI.

### 7. country-flag-icons
- **Project**: https://gitlab.com/catamphetamine/country-flag-icons
- **License**: MIT License (`MIT`)
- **Usage**: Crisp vector SVG country flags for node region badges.

## Complete Dependency Graph

All Rust crates and JavaScript packages used to build Bypax are governed by their respective open-source licenses (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `0BSD`, `ISC`, `MPL-2.0`). Refer to `Cargo.lock` and `pnpm-lock.yaml` in this repository for exact dependency versions and provenance.
