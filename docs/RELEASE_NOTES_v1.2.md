# 四信路由器通信诊断工具 v1.2 Release Candidate Notes

## Scope

v1.2 extends the original WAN diagnosis/PCAP streaming tool into a field-oriented layered diagnostic workflow while retaining the two-Telnet architecture and router-side no-PCAP-file constraint.

## Main additions

- Default Telnet credentials `admin/admin`.
- Master-station IP and business-port workflow, default port `2404`.
- Master Ping and capture with `host <master> and (icmp or tcp port <port>)` so 140-byte IPv4 ICMP evidence is not filtered out.
- Master-station Ping is auxiliary only: ordinary Echo timeout/100% loss is treated as inconclusive because the master may disable ICMP; diagnosis continues with the configured TCP business port. Explicit `Network is unreachable` / `Destination Host Unreachable` remains an IP-layer failure.
- Ethernet-terminal workflow: validate terminal IPv4 + terminal TCP port, use Ping as auxiliary evidence, and still capture `br0` with `host <terminalIP> and (icmp or tcp port <terminalPort>)` when ICMP has no reply.
- Serial-terminal mode based on DTS/systemlog evidence only; `/dev/ttyUSB*` is treated as cellular-module control evidence, not as an external terminal serial port.
- Context-aware cellular diagnosis that separates AT/module, SIM, registration and WAN/IP failures.
- TCP payload extraction and lightweight IEC60870-5-104 / IEC60870-5-101 recognition.
- Business-data diagnosis unifies ordinary IEC101/104 and State Grid encrypted 101/104 evidence into one layer; encrypted payload is still never falsely decoded.
- Six-layer field report with operator-oriented evidence, conclusions and suggested checks. TCP sessions are diagnosed per exact `IP:port` pair for established/refused/unanswered/incomplete-handshake/FIN/RST and payload direction states.
- Online capture and offline PCAP reuse the same packet/protocol analysis chain.

## Safety rules

- Automatic diagnosis does not execute `nvram set` or `nvram commit`.
- A generic `ERROR`, `+CME ERROR`, or `attach_check: status=0` is not sufficient by itself for a fatal diagnosis.
- Encrypted payload is never reported as decrypted without keys.
- Sample command-byte sequences such as `80 20/21/22/23`, `50/51`, and repeated `56` are treated as current-site sample baselines, not universal protocol semantics.

## Validation

Use `verify_v1.2_debug.bat` from a Visual Studio 2022 Developer Command Prompt. It configures x64 with Qt 6.8.3 by default, builds all targets, runs the complete CTest suite, and checks that diagnostic production code contains no NVRAM write command.

The program may print `libpng warning: tRNS: invalid with alpha channel` on some Windows setups. If the UI renders normally, this is a non-blocking PNG metadata/resource warning and does not affect diagnosis or packet analysis.

## Field operation workflow alignment

- Added connection history and explicit disconnect action.
- After control-login, automatically reads `wan_ifname`, `wan_ipaddr`, and `ifconfig`/`ip -4 addr`, then displays interface-to-IPv4 mapping and fills the WAN capture interface when identifiable.
- Added independent remote Ping, command, and module-log windows. Each uses its own Telnet session so long-running logs/Ping do not block the diagnostic control session.
- Added quick capture-port presets (`全部`, `2404`, `5051`, `自定义`) while preserving the safe binary-PCAP streaming pipeline.
- Separated real-time operation logs from the six-layer diagnosis report so diagnosis updates no longer overwrite runtime history.
- `/dev/ttyUSB*` remains classified as cellular-module AT/control evidence, not terminal serial communication.

- 离线分析新增 `tcpdump文本→PCAP`：可把带 `0x0000/0x0010...` 十六进制帧的 PuTTY/tcpdump 文本日志恢复为 Classic PCAP，并自动进入离线分析；不完整帧只提示并跳过，不伪造缺失字节。
