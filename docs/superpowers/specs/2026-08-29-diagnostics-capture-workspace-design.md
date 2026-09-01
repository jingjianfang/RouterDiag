# Diagnostics Capture Workspace Design

## Scope
Keep six internal diagnostic layers but aggregate them into four presentation layers. Correct NVRAM log configuration and AT parsing. Make tcpdump text fallback incremental. Allow detachable tabs. Add reusable capture sessions with concurrent network-Telnet captures and one-at-a-time physical serial captures. Add master/terminal TCP roles and actual-master endpoint discovery. Add shortcut command JSON import/export.

## Diagnostic model
Internal layers remain CELLULAR_MODULE, SIM, REGISTRATION, WAN, TRANSPORT, BUSINESS_DATA. UI/report groups CELLULAR_MODULE+SIM+REGISTRATION as `1 模组 / SIM / 网络注册`, then WAN, TRANSPORT, BUSINESS_DATA.

Master and terminal each have role Client/Server. Defaults: master Client, terminal Server. A configurable 60 second expected-connection window is used by one-click diagnosis. For a master client, the configured master IP is advisory. Capture discovery uses business port/direction to identify actual remote IP; mismatches are reported as NAT/cluster/alternate endpoint hints, not faults.

For serial terminal communication: if valid master->WAN TCP payload is observed but no WAN->master payload response is observed during the window, diagnose toward serial terminal/config/wiring and include captured downstream payload HEX/ASCII/protocol evidence.

## Router system log policy
System log enabled with `debuglog_enable=1`, commit after each set. Network Telnet log tail requires `syslogd_enable=3`, commit, then `tail /tmp/.systemlog -f`. Physical router serial log output uses `syslogd_enable=0`, commit. Existing correct values are not rewritten.

## Capture model
Each capture session owns transport, parser, analyzer, storage and UI. Network login may run multiple parallel Telnet capture sessions. Physical serial login permits one active capture session. `any` is accepted without `ifconfig any` preflight. BPF is user editable; advanced tcpdump arguments are accepted but arbitrary shell chaining is not.

Binary PCAP remains preferred for network Telnet. If the PCAP global header is absent without a fatal tcpdump error, switch to `tcpdump -xx` and parse incrementally: completed packets are emitted immediately, written to PCAP incrementally, and displayed before stop.

One-click diagnosis with Ethernet terminal starts synchronized terminal-side and master/WAN-side capture sessions. If both resolve to the same interface, one session is shared. The report compares both evidence sets.

## UI
All principal and nested tabs are detachable. Closing a detached window reattaches the same widget, preserving state. Capture workspace supports `+ 新建抓包` and independent sessions/windows.

## Shortcut commands
Builtin `ifconfig` is named `ifconfig`; `tail /tmp/.systemlog -f` is a standalone builtin. Export JSON includes builtin and custom entries. Import creates custom copies only and never modifies builtin entries.
