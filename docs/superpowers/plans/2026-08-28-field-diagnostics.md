# Field Diagnostics Integration Implementation Plan
> **OBSOLETE / SUPERSEDED:** This early plan predates the corrected v1.2 design. Do not implement its `/dev/ttyUSB0` terminal-serial assumptions. Use `2026-08-28-field-diagnostics-v1.2.md` and the v1.2 spec instead.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add master-station, Ethernet-terminal, serial-test, system-log, and command-terminal diagnostics to the existing Qt WAN/PCAP tool while preserving direct binary PCAP streaming to the PC.

**Architecture:** Keep the existing control/capture Telnet split. Add a small control-operation coordinator so only one command workflow owns the control Telnet session at a time, add focused parsers/builders for ping/field diagnostics, extend packet metadata/evidence, and expose the new workflows in `MainWindow` without duplicating capture logic.

**Tech Stack:** C++17, Qt 6/Qt 5 compatible Core/Network/Widgets/Test, CMake, MSVC 2022.

**Spec:** `docs/superpowers/specs/2026-08-28-field-diagnostics-design.md`

## Global Constraints

- Router PCAP capture must remain `tcpdump -w -` streamed directly to the PC; no router-side PCAP file.
- Default Telnet host/port/user/password are `192.168.1.1`, `23`, `admin`, `admin`.
- Default business port is `2404`.
- Default terminal bridge is `br0`.
- Default serial device is `/dev/ttyUSB0`.
- NVRAM mutation is only allowed from an explicit user action.
- Only one control-Telnet command operation may run at a time.
- Existing offline PCAP import/replay must continue to work.

---

### Task 1: Add field diagnostic result types and ping parser

**Files:**
- Create: `diagnostic/FieldDiagnosticTypes.h`
- Create: `diagnostic/PingParser.h`
- Create: `diagnostic/PingParser.cpp`
- Test: `tests/test_pingparser.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Produces: `enum class PingState { Unknown, Reachable, Unreachable, Timeout, Error };`
- Produces: `struct PingResult { PingState state; int transmitted; int received; QString target; QString raw; };`
- Produces: `PingResult PingParser::parse(const QString& target, const QString& output);`

- [ ] **Step 1: Write failing ping parser tests**

```cpp
void busyboxSuccess(){
    const auto r=PingParser::parse("192.168.1.10", "3 packets transmitted, 3 packets received, 0% packet loss");
    QCOMPARE(r.state, PingState::Reachable);
    QCOMPARE(r.received, 3);
}
void unreachable(){
    const auto r=PingParser::parse("192.168.1.10", "3 packets transmitted, 0 packets received, 100% packet loss");
    QCOMPARE(r.state, PingState::Unreachable);
}
void timeoutMarker(){
    const auto r=PingParser::parse("192.168.1.10", "\n[COMMAND TIMEOUT]");
    QCOMPARE(r.state, PingState::Timeout);
}
```

- [ ] **Step 2: Run `test_pingparser` and verify it fails because `PingParser` does not exist**

Run:

```cmd
cmake --build out\build\debug --config Debug --target test_pingparser
```

Expected: compile failure for missing `diagnostic/PingParser.h`.

- [ ] **Step 3: Implement the minimal parser**

Parse both `N packets transmitted, M packets received` and `N packets transmitted, M received`, then map `received > 0` to Reachable, zero received to Unreachable, `[COMMAND TIMEOUT]` to Timeout, and obvious `bad address`/`unknown host`/`not found` text to Error.

- [ ] **Step 4: Run the ping parser test**

Run:

```cmd
ctest --test-dir out\build\debug -C Debug -R test_pingparser --output-on-failure
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add diagnostic/FieldDiagnosticTypes.h diagnostic/PingParser.* tests/test_pingparser.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: add ping result parser"
```

### Task 2: Add safe field command builders

**Files:**
- Create: `diagnostic/FieldCommandBuilder.h`
- Create: `diagnostic/FieldCommandBuilder.cpp`
- Test: `tests/test_fieldcommandbuilder.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Produces: `static bool isValidIpv4(const QString& value);`
- Produces: `static QString sanitizeInterface(const QString& value);`
- Produces: `static QString sanitizeSerialDevice(const QString& value);`
- Produces: `static QString buildPingCommand(const QString& ipv4);`
- Produces: `static QString buildMasterFilter(const QString& ipv4, quint16 port);`
- Produces: `static QString buildTerminalFilter(const QString& ipv4);`
- Produces: `static QString buildSerialTestCommand(const QString& device);`

- [ ] **Step 1: Write failing command-builder tests**

```cpp
void terminalFilter(){
    QCOMPARE(FieldCommandBuilder::buildTerminalFilter("192.168.1.20"), QString("host 192.168.1.20"));
}
void masterFilter(){
    QCOMPARE(FieldCommandBuilder::buildMasterFilter("90.15.80.82",2404), QString("host 90.15.80.82 and port 2404"));
}
void rejectInjection(){
    QVERIFY(FieldCommandBuilder::buildPingCommand("1.1.1.1;reboot").isEmpty());
    QVERIFY(FieldCommandBuilder::buildSerialTestCommand("/dev/ttyUSB0;reboot").isEmpty());
}
```

- [ ] **Step 2: Run the test and verify it fails for missing builder**
- [ ] **Step 3: Implement using `QHostAddress` for IPv4 validation and strict character allow-lists for interface/device names**

Use a bounded ping command:

```cpp
return QStringLiteral("ping -c 3 -W 2 %1 2>&1").arg(ipv4);
```

Serial device allow-list: `/`, ASCII letters/digits, `_`, `.`, `-` only; require prefix `/dev/`.

- [ ] **Step 4: Run `test_fieldcommandbuilder` and verify PASS**
- [ ] **Step 5: Commit**

```bash
git add diagnostic/FieldCommandBuilder.* tests/test_fieldcommandbuilder.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: add safe field command builders"
```

### Task 3: Extend packet metadata and target-aware TCP evidence

**Files:**
- Modify: `capture/PcapTypes.h`
- Modify: `capture/PacketParser.cpp`
- Modify: `capture/PacketAnalyzer.h`
- Modify: `capture/PacketAnalyzer.cpp`
- Test: `tests/test_packetparser.cpp`
- Test: `tests/test_packetanalyzer.cpp`

**Interfaces:**
- `ParsedPacket` adds `quint16 ipTotalLength`, `quint32 tcpPayloadLength`.
- `CaptureStats` adds `quint64 tcpSynAck`, `quint64 tcpAck`, `quint64 tcpPshAck`, `quint64 tcpPayloadPackets`, `quint64 icmpLength140`.
- `PacketAnalyzer` adds `TcpChannelEvidence evidenceFor(const QString& targetIp, quint16 targetPort) const;`.

- [ ] **Step 1: Add failing parser tests for IPv4 total length and TCP payload length**

Build a minimal TCP frame with IP total length 44, TCP header length 20, and 4 bytes payload; assert `ipTotalLength == 44` and `tcpPayloadLength == 4`.

- [ ] **Step 2: Add failing analyzer tests for SYN → SYN+ACK → ACK and PSH+ACK**

```cpp
QVERIFY(e.threeWayHandshake);
QVERIFY(e.pshAckPayloadSeen);
QCOMPARE(e.payloadPackets, quint64(1));
```

- [ ] **Step 3: Run `test_packetparser` and `test_packetanalyzer`; verify failures**
- [ ] **Step 4: Implement parser metadata and analyzer counters/evidence**

TCP payload length is `max(0, ipTotalLength - ihl - tcpHeaderLength)` bounded by captured bytes. Count ICMP length-140 evidence using `ipTotalLength == 140` rather than raw Ethernet frame size.

- [ ] **Step 5: Run both tests and verify PASS**
- [ ] **Step 6: Commit**

```bash
git add capture/PcapTypes.h capture/PacketParser.cpp capture/PacketAnalyzer.* tests/test_packetparser.cpp tests/test_packetanalyzer.cpp
git commit -m "feat: add TCP channel evidence"
```

### Task 4: Add a control-operation coordinator

**Files:**
- Create: `diagnostic/ControlOperationCoordinator.h`
- Create: `diagnostic/ControlOperationCoordinator.cpp`
- Test: `tests/test_controloperationcoordinator.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Produces: `enum class ControlOperation { Idle, WanDiagnosis, PingMaster, PingTerminal, SerialTest, LogRead, ShellCommand, CaptureStop, EnableDetailedLog };`
- Produces: `bool tryAcquire(ControlOperation op);`
- Produces: `void release(ControlOperation op);`
- Produces: `bool isBusy() const;`
- Signal: `busyChanged(bool)`.

- [ ] **Step 1: Write failing ownership tests**

```cpp
QVERIFY(c.tryAcquire(ControlOperation::PingTerminal));
QVERIFY(!c.tryAcquire(ControlOperation::ShellCommand));
c.release(ControlOperation::PingTerminal);
QVERIFY(c.tryAcquire(ControlOperation::ShellCommand));
```

- [ ] **Step 2: Run test and verify failure**
- [ ] **Step 3: Implement exact-owner release semantics**
- [ ] **Step 4: Run test and verify PASS**
- [ ] **Step 5: Commit**

### Task 5: Route WAN diagnosis and capture-stop control through the coordinator

**Files:**
- Modify: `diagnostic/DiagnosticController.h`
- Modify: `diagnostic/DiagnosticController.cpp`
- Modify: `capture/PacketCaptureController.h`
- Modify: `capture/PacketCaptureController.cpp`
- Modify: `MainWindow.cpp`
- Test: `tests/test_controloperationcoordinator.cpp`

**Interfaces:**
- `DiagnosticController` receives `ControlOperationCoordinator*` in its constructor.
- `PacketCaptureController` receives the same coordinator for stop commands.

- [ ] **Step 1: Add failing tests that `WanDiagnosis` blocks `ShellCommand` and releases on finish/cancel**
- [ ] **Step 2: Update constructors and acquire/release ownership around workflows**
- [ ] **Step 3: Ensure all early failure paths release the owner**
- [ ] **Step 4: Build existing tests and run full `ctest`**
- [ ] **Step 5: Commit**

### Task 6: Add field operation controller for ping, serial test, logs, and shell commands

**Files:**
- Create: `diagnostic/FieldOperationController.h`
- Create: `diagnostic/FieldOperationController.cpp`
- Test: `tests/test_fieldoperationcontroller.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- `void pingMaster(const QString& ip);`
- `void pingTerminal(const QString& ip);`
- `void testSerial(const QString& device);`
- `void readRecentLog();`
- `void readLogStatus();`
- `void enableDetailedLog();`
- `void executeShellCommand(const QString& command);`
- Signals: `pingFinished(kind, PingResult)`, `textResult(kind, command, output)`, `failed(kind, reason)`.

- [ ] **Step 1: Write tests around command selection and coordinator rejection using a fake command transport**
- [ ] **Step 2: Refactor command execution dependency behind a minimal interface if needed; do not duplicate Telnet parsing**
- [ ] **Step 3: Implement ping/serial/log/shell workflows**
- [ ] **Step 4: Implement explicit detailed-log command sequence: set debuglog, set syslogd, commit**
- [ ] **Step 5: Run controller tests and full `ctest`**
- [ ] **Step 6: Commit**

### Task 7: Add field report builder

**Files:**
- Create: `report/FieldReportBuilder.h`
- Create: `report/FieldReportBuilder.cpp`
- Test: `tests/test_fieldreportbuilder.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Produces: `QString buildMasterSection(const QString& ip, quint16 port, const PingResult&, const TcpChannelEvidence&);`
- Produces: `QString buildEthernetTerminalSection(const QString& ip, const QString& iface, const PingResult&, const CaptureStats&, const QStringList& conversations);`
- Produces: `QString buildSerialSection(const QString& device, const QString& output);`

- [ ] **Step 1: Write failing exact-text fragment tests**

Verify reports contain facts such as `TCP 2404 三次握手：已观察到`, `PSH+ACK 业务载荷：已观察到`, `终端 Ping：成功`, and `未在抓包时间窗内观察到匹配流量`.

- [ ] **Step 2: Run test and verify failure**
- [ ] **Step 3: Implement report sections without overclaiming end-to-end health**
- [ ] **Step 4: Run test and verify PASS**
- [ ] **Step 5: Commit**

### Task 8: Update UI defaults and add field diagnostics controls

**Files:**
- Modify: `MainWindow.ui`
- Modify: `MainWindow.h`
- Modify: `MainWindow.cpp`

**Interfaces:**
- UI names: `editMasterIp`, `spinBusinessPort`, `comboTerminalMode`, `stackTerminalMode`, `editTerminalIp`, `editTerminalIface`, `btnPingTerminal`, `btnCaptureTerminal`, `editSerialDevice`, `btnSerialTest`, `btnPingMaster`, `btnCaptureMaster`, `tabResults`, `txtSystemLog`, `editShellCommand`, `btnShellExecute`, `comboQuickCommand`, `btnReadLog`, `btnReadLogStatus`, `btnEnableDetailedLog`.

- [ ] **Step 1: Change connection defaults to `admin/admin` and add field diagnostic group**
- [ ] **Step 2: Add Ethernet/Serial stacked controls with defaults `br0` and `/dev/ttyUSB0`**
- [ ] **Step 3: Add result tabs for diagnosis, log, and command terminal while preserving packet table below**
- [ ] **Step 4: Run Qt UIC directly**

Run:

```cmd
C:\Qt\6.8.3\msvc2022_64\bin\uic.exe MainWindow.ui -o ui_MainWindow_test.h
```

Expected: exit code 0 with no XML/UIC errors.

- [ ] **Step 5: Delete the generated test header and commit UI changes**

### Task 9: Wire master and terminal workflows into MainWindow

**Files:**
- Modify: `MainWindow.h`
- Modify: `MainWindow.cpp`

**Interfaces:**
- `startCaptureFor(iface, filter, label)` helper centralizes capture startup.
- Master capture calls existing `PacketCaptureController::start(wanIface, masterFilter)`.
- Terminal capture calls existing `PacketCaptureController::start(terminalIface, terminalFilter)`.

- [ ] **Step 1: Wire terminal-mode switching and validation**
- [ ] **Step 2: Wire master ping and capture**
- [ ] **Step 3: Wire terminal ping and `br0 host <terminal-ip>` capture**
- [ ] **Step 4: Wire serial test, log operations, detailed-log confirmation dialog, and shell command quick actions**
- [ ] **Step 5: Update status/report text when field operations complete**
- [ ] **Step 6: Build `WanDiagTool` and manually open the UI without a router**
- [ ] **Step 7: Commit**

### Task 10: Add offline field-analysis fixtures and regression coverage

**Files:**
- Create: `samples/demo_master_channel.pcap`
- Create: `samples/demo_terminal_br0.pcap`
- Modify: `README.md`
- Modify: `docs/TESTING.md`

**Interfaces:**
- Master fixture contains a SYN/SYN+ACK/ACK exchange and a PSH+ACK packet to/from a synthetic master IP on TCP 2404.
- Terminal fixture contains packets to/from a synthetic terminal IP and ICMP traffic.

- [ ] **Step 1: Generate deterministic Classic PCAP fixtures**
- [ ] **Step 2: Document offline validation steps**
- [ ] **Step 3: Run full test suite**

Run:

```cmd
ctest --test-dir out\build\debug -C Debug --output-on-failure
```

Expected: all tests PASS.

- [ ] **Step 4: Build application**

```cmd
cmake --build out\build\debug --config Debug --target WanDiagTool
```

Expected: `WanDiagTool.exe` produced successfully.

- [ ] **Step 5: Commit**

### Task 11: Package v1.2 patch and full source archive

**Files:**
- Package all changed source/docs/samples; exclude `.git`, `out`, `.vs`, and build products.

- [ ] **Step 1: Run archive integrity tests**
- [ ] **Step 2: Produce `WanDiagTool_Qt_VS2022_v1.2_field_diagnostics.zip`**
- [ ] **Step 3: Produce `WanDiagTool_v1.2_field_diagnostics_patch.zip`**
- [ ] **Step 4: List exact Windows configure/build commands for the user's Qt 6.8.3 MSVC2022_64 environment**
