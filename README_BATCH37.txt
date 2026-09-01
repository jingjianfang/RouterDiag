FourFaith RouterDiag v1.3 RC13 - Batch37 Field Config Snapshot Support

Purpose
-------
Batch37 improves diagnosis reliability using real Four-Faith field configuration snapshots, while keeping real-time interface, route and AT evidence authoritative.

Supported offline inputs
------------------------
1. `nvram show` text (`key=value`).
2. Four-Faith binary configuration export: magic `FOUR-FAITH:`, one format-version byte, followed by repeated records encoded as: u8 key length + key bytes + u16 little-endian value length + value bytes.

Diagnostic behavior
-------------------
- Distinguishes primary WAN and backup WAN instead of treating any cached WAN IP as current connectivity.
- An offline snapshot WAN IP is only an advisory hint. A later live interface/default-route discovery clears snapshot provenance and becomes authoritative.
- When saved `wan_ifname/wan_ipaddr` disagree with the current default-route egress, the live IPv4 bound to the default-route interface wins. A standalone `bkup_wan_ipaddr` remains backup-path evidence only.
- Separates configured module identity from runtime/communication identity. A mismatch is reported as context, not automatically as a module fault.
- Uses NVRAM SIM/RAT/signal fields as secondary evidence only. RAT text never fabricates CEREG/CGREG/CREG/C5GREG registration success.
- Handles both DTS profile 1 and profile 2 (`*_2`) and selects the connected profile when available.
- Binary/text snapshots are parsed through a diagnostic whitelist. The full imported NVRAM content is never dumped into the runtime log/report. Credentials and device identifiers are not copied into Batch37 tests or release artifacts.

UI
--
The former “导入系统日志” action is now “导入日志/配置” and accepts `.txt`, `.log` and `.bin`.

Verification scope
------------------
- Batch15-Batch37 static contracts.
- Release packaging contract.
- `MainWindow.ui` XML validation.
- CMake configure is attempted, but a complete Qt build still requires a machine with the Qt SDK installed (Windows + the project Qt/MSVC kit is the intended release environment).

Field data policy
-----------------
The supplied field snapshots are validation inputs only and are not bundled in the source/patch archives.
