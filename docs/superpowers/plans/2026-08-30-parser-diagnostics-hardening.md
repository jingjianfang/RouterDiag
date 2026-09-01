# Parser and Diagnostics Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve real-device parsing and diagnostic accuracy across AT registration, tcpdump link layers, TCP session analysis, system-log state, synchronized capture, Telnet command framing, IEC104 state tracking, packet correlation, and long-running capture memory use.

**Architecture:** Add focused parsers/state helpers instead of duplicating heuristics in MainWindow/DiagnosisEngine/LogAnalyzer. Preserve existing public workflow while making capture sessions stream to disk and UI bounded. Add deterministic tests/contracts for each new behavior.

**Tech Stack:** C++17, Qt 5/6 Core/Network/Widgets/SerialPort/Test, CMake.

**Spec:** Confirmed in chat on 2026-08-30.

## Global Constraints
- Keep Windows + VS2022 + Qt 6.8.3 packaging compatible.
- Do not require new third-party libraries.
- Preserve current network/serial login and multi-capture behaviors.
- Configuration master IP remains a reference; actual TCP peer drives client-role diagnosis.

---

### Task 1: AT registration parser
- [ ] Add structured 3GPP registration result parser and CME descriptions.
- [ ] Use it in LogAnalyzer, DiagnosisEngine, and DeviceDiscovery results.
- [ ] Add tests for 1-field and n,stat extended forms.

### Task 2: PCAP/tcpdump link-layer coverage
- [ ] Add Linux SLL2 and multi-VLAN/QinQ parsing.
- [ ] Extend tcpdump text parser link-type detection/length framing.
- [ ] Add packet parser tests.

### Task 3: TCP analyzer accuracy
- [ ] Count retransmissions only for duplicate payload-bearing segments.
- [ ] Clear pending SYN on RST response.
- [ ] Add main-session selection and historical anomalies.
- [ ] Add tests.

### Task 4: Live system-log state aging
- [ ] Separate current failure flags from historical event counters/timestamps.
- [ ] Merge live snapshots without sticky current flags.
- [ ] Keep history in report evidence.

### Task 5: Synchronized capture coordinator and packet correlation
- [ ] Stop sibling session when either side fails/closes.
- [ ] Correlate payload packets across terminal/WAN capture by payload hash, sequence/length/time.
- [ ] Emit forwarding conclusions and delay statistics.

### Task 6: Telnet command completion framing
- [ ] Learn stable prompt where possible.
- [ ] Add unique command-completion marker for ordinary commands without breaking streaming tcpdump/tail commands.
- [ ] Parse exit status and remove marker from output.

### Task 7: AT telemetry expansion
- [ ] Query CGATT, CSQ, COPS in addition to CPIN/registration commands.
- [ ] Parse operator/RAT and CME errors.
- [ ] Expose fields to status/report.

### Task 8: IEC104 session state
- [ ] Track STARTDT/STOPDT/TESTFR handshakes, I-frame send/receive sequence progression and acknowledgements.
- [ ] Detect gaps, duplicate I frames, and outstanding unacknowledged sequences.
- [ ] Add tests and protocol diagnosis output.

### Task 9: Long-running capture limits
- [ ] Stream all PCAP bytes to a temporary file by default.
- [ ] Bound capture table rows to 20,000 while preserving total counters.
- [ ] Export complete temp PCAP without loading entire capture into RAM.

### Task 10: Verification
- [ ] Add Batch30 static contract covering all structural guarantees.
- [ ] Run Batch15-30 and release packaging contract.
- [ ] Validate MainWindow.ui XML.
- [ ] Package source and patch.
