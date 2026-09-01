# WanDiagTool v1.2 Field Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a layered field-diagnostics workflow that distinguishes cellular/SIM/registration/WAN faults, router-to-master and router-to-terminal transport faults, State Grid security/encryption exchange faults, and IEC101/104 application faults.

**Architecture:** Keep the existing two-Telnet and binary-PCAP-stream architecture intact. Extend the existing WAN log model, add focused channel and protocol analyzers, then compose their structured evidence into a new field diagnosis report; the UI only collects parameters and renders results. `/dev/ttyUSB*` remains cellular-module evidence and is never used as the default terminal serial endpoint.

**Tech Stack:** C++17, Qt 6/Qt 5 compatible Core/Network/Widgets/Test, CMake, MSVC 2022, Classic PCAP stream reader.

**Spec:** `docs/superpowers/specs/2026-08-28-field-diagnostics-design.md`

## Global Constraints

- Preserve router-side no-PCAP-file behavior: capture uses `tcpdump -U -s 0 -w -` over the dedicated capture Telnet connection.
- Default Telnet username is `admin`; default Telnet password is `admin`.
- Default master/business port is `2404`.
- Terminal serial diagnosis must not assume `/dev/ttyUSB0` or any `/dev/ttyUSB*` device.
- `EB ... D7` is analyzed as State Grid security/encryption framing, separately from IEC101/104 business decoding.
- A single `ERROR`, `+CME ERROR`, or `attach_check: status=0` is never sufficient by itself for a fatal diagnosis.
- Automatic diagnosis must not silently modify NVRAM.
- Existing Telnet IAC decoding and PCAP streaming architecture must remain compatible.

---

### Task 1: Expand diagnostic domain types and add realistic fixtures

**Files:**
- Modify: `diagnostic/DiagnosticTypes.h`
- Create: `tests/fixtures/sim_not_detected.txt`
- Create: `tests/fixtures/registration_failed.txt`
- Create: `tests/fixtures/normal_cellular_and_dts.txt`
- Create: `tests/fixtures/grid_security_normal.txt`
- Create: `tests/fixtures/grid_security_repeated_56.txt`
- Modify: `tests/test_loganalyzer.cpp`

**Interfaces:**
- Produces: `enum class LayerState { Unknown, NotTested, Normal, Warning, Error }`
- Produces: `enum class Confidence { Low, Medium, High }`
- Produces: `struct LayerDiagnosis { QString layer; LayerState state; Confidence confidence; QString conclusion; QStringList evidence; QStringList suggestions; }`
- Produces: `struct FieldDiagnosisReport { QList<LayerDiagnosis> layers; QString overallConclusion; }`
- Extends: `WanStatus` with AT/SIM/registration/DTS fields used by later tasks.

- [ ] **Step 1: Add failing log-model tests before changing production code**

Add test cases asserting these exact behaviors:

```cpp
void simErrorStillDetectsModule(){
    QFile f(QFINDTESTDATA("fixtures/sim_not_detected.txt"));
    QVERIFY(f.open(QIODevice::ReadOnly));
    const WanStatus s=LogAnalyzer::analyze(QString::fromUtf8(f.readAll()));
    QVERIFY(s.moduleAtResponsive);
    QCOMPARE(s.moduleName, QString("N720"));
    QVERIFY(s.cpinErrorCount >= 2);
    QCOMPARE(s.simStatus, QString("ERROR"));
}

void registrationFixtureSeparatesSimAndRegistration(){
    QFile f(QFINDTESTDATA("fixtures/registration_failed.txt"));
    QVERIFY(f.open(QIODevice::ReadOnly));
    const WanStatus s=LogAnalyzer::analyze(QString::fromUtf8(f.readAll()));
    QCOMPARE(s.simStatus, QString("READY"));
    QCOMPARE(s.cereg, QString("0,8"));
    QCOMPARE(s.cgreg, QString("2,8"));
    QCOMPARE(s.wanIp, QString("0.0.0.0"));
    QVERIFY(s.networkUnreachableCount > 0);
}

void dtsTcpOverridesSerialConfigAsObservedTransport(){
    QFile f(QFINDTESTDATA("fixtures/normal_cellular_and_dts.txt"));
    QVERIFY(f.open(QIODevice::ReadOnly));
    const WanStatus s=LogAnalyzer::analyze(QString::fromUtf8(f.readAll()));
    QCOMPARE(s.serialBaudrate, 115200);
    QCOMPARE(s.dcuIp, QString("192.168.2.101"));
    QCOMPARE(s.dcuPort, 2404);
    QVERIFY(s.southTcpConnected);
}
```

- [ ] **Step 2: Run tests and verify compile/test failure**

Run:

```cmd
cmake --build out\build\debug --config Debug --target test_loganalyzer
ctest --test-dir out\build\debug -C Debug -R test_loganalyzer --output-on-failure
```

Expected: compile failure because the new `WanStatus` fields do not yet exist.

- [ ] **Step 3: Extend `DiagnosticTypes.h` minimally**

Add fields with stable names:

```cpp
bool moduleAtResponsive = false;
int cpinErrorCount = 0;
QString cpinRaw;
QString simCardRaw;
QString cereg;
QString mcc;
QString mnc;
QString lac;
QString cellId;
int pci = -1;
QString band;
int earfcn = -1;
int rssi = 999;
int dialFinish = -1;
int networkUnreachableCount = 0;
int dcucom = -1;
QString dcuIp;
int dcuPort = -1;
int serialBaudrate = -1;
int serialDatabit = -1;
int serialStopbit = -1;
int serialParity = -1;
int serialFlowcontrol = -1;
bool dtsStarted = false;
bool southTcpConnected = false;
```

Add the layer/report types named in **Interfaces**.

- [ ] **Step 4: Create compact fixtures from the supplied logs**

Each fixture must keep only the smallest evidence sequence needed by its tests, including command context. Do not copy unrelated thousands of lines.

- [ ] **Step 5: Re-run the targeted test**

Expected: tests compile; newly added behavioral assertions still fail until Task 2.

- [ ] **Step 6: Commit**

```bash
git add diagnostic/DiagnosticTypes.h tests/fixtures tests/test_loganalyzer.cpp
git commit -m "test: add layered field diagnosis fixtures"
```

---

### Task 2: Make LogAnalyzer context-aware for SIM, registration, WAN, and DTS

**Files:**
- Modify: `diagnostic/LogAnalyzer.cpp`
- Modify: `tests/test_loganalyzer.cpp`

**Interfaces:**
- Consumes: extended `WanStatus` from Task 1.
- Produces: populated AT/SIM/registration/DTS fields without producing final diagnosis text.

- [ ] **Step 1: Add failing assertions for AT command context and normal-WAN safeguards**

Add:

```cpp
void attachStatusZeroDoesNotEraseValidWan(){
    const WanStatus s=LogAnalyzer::analyze(
        "4G_MAIN_Q: AT+CGATT?\n4G_MAIN_A:\n+CGATT: 1\nOK\n"
        "[data=wan_ipaddr  value=10.4.106.210]\n"
        "attach_check: status = 0, bret = 1, bOld = 1\n"
        "wanface=usb0\n");
    QCOMPARE(s.cgatt, 1);
    QCOMPARE(s.wanIp, QString("10.4.106.210"));
    QCOMPARE(s.wanIfname, QString("usb0"));
}

void ttyUsbIsModuleControlEvidenceOnly(){
    const WanStatus s=LogAnalyzer::analyze(
        "CONTROL DEVICES /dev/ttyUSB2\n4G_MAIN_Q: ATI\n4G_MAIN_A:\nNEOWAY\nN720\nV009\nOK\n");
    QVERIFY(s.moduleAtResponsive);
    QCOMPARE(s.moduleControlDevice, QString("/dev/ttyUSB2"));
}
```

Add `QString moduleControlDevice;` to `WanStatus` if not already present.

- [ ] **Step 2: Run the focused test and observe failure**

Run the same `test_loganalyzer` command as Task 1.

- [ ] **Step 3: Implement command/response tracking**

Keep `currentCmd`, but also track response blocks sufficiently to associate `ERROR` with `AT+CPIN?` and successful ATI responses. Required behavior:

```cpp
if (currentCmd.startsWith("ATI", Qt::CaseInsensitive) && line == "OK")
    s.moduleAtResponsive = true;

if (currentCmd.startsWith("AT+CPIN?", Qt::CaseInsensitive) && line == "ERROR") {
    ++s.cpinErrorCount;
    s.cpinRaw = "ERROR";
}
```

Do not make every generic `ERROR` a SIM failure.

- [ ] **Step 4: Parse registration and DTS configuration fields**

Parse the exact log families used by the fixtures:

```text
+CEREG: ...
+CGREG: ...
+C5GREG: ...
mcc[...] = ...
mnc[...] = ...
Get BAND: ...
Get EARFCN: ...
[name= rssi data= ...]
[name= DialFinish data= ...]
dcucom=...
dcu_ip=..., dcu_port=...
serial1 baudrate=...
databit=..., stopbit=..., parity=..., flowcontrol=...
DTS App start..
south tcp client config connect
tcp client connect ok
connect error: Network is unreachable
```

- [ ] **Step 5: Preserve existing PPP behavior**

Run:

```cmd
ctest --test-dir out\build\debug -C Debug -R "test_loganalyzer|test_diagnosisengine" --output-on-failure
```

Expected: existing IPCP fixture remains green.

- [ ] **Step 6: Commit**

```bash
git add diagnostic/LogAnalyzer.cpp tests/test_loganalyzer.cpp
git commit -m "feat: parse cellular and DTS evidence with context"
```

---

### Task 3: Replace single-result WAN diagnosis with layered cellular decisions

**Files:**
- Modify: `diagnostic/DiagnosisEngine.h`
- Modify: `diagnostic/DiagnosisEngine.cpp`
- Modify: `tests/test_diagnosisengine.cpp`

**Interfaces:**
- Keeps: `static DiagnosisResult diagnose(const WanStatus&)` for backward compatibility.
- Adds: `static QList<LayerDiagnosis> diagnoseWanLayers(const WanStatus&)`.
- Produces layer names exactly: `CELLULAR_MODULE`, `SIM`, `REGISTRATION`, `WAN`.

- [ ] **Step 1: Write failing tests for precise classification**

Add:

```cpp
void atiOkCpinErrorIsSimNotModule(){
    WanStatus s;
    s.moduleAtResponsive=true;
    s.moduleName="N720";
    s.cpinErrorCount=3;
    s.simStatus="ERROR";
    s.wanIp="0.0.0.0";
    const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
    QCOMPARE(layers[0].state, LayerState::Normal);
    QCOMPARE(layers[1].state, LayerState::Error);
    QVERIFY(layers[1].conclusion.contains("SIM"));
}

void readySimButRegistrationBad(){
    WanStatus s;
    s.moduleAtResponsive=true;
    s.simStatus="READY";
    s.cereg="0,8";
    s.cgreg="2,8";
    s.c5greg="2,4";
    s.wanIp="0.0.0.0";
    s.networkUnreachableCount=3;
    const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
    QCOMPARE(layers[1].state, LayerState::Normal);
    QCOMPARE(layers[2].state, LayerState::Error);
}

void validWanWinsOverAttachStatusNoise(){
    WanStatus s;
    s.moduleAtResponsive=true;
    s.simStatus="READY";
    s.cgatt=1;
    s.wanIp="10.4.106.210";
    QCOMPARE(DiagnosisEngine::diagnose(s).type, QString("WAN_NORMAL"));
}
```

- [ ] **Step 2: Run and observe missing API failure**

- [ ] **Step 3: Implement independent layer rules**

Required rule ordering:

```text
module: ATI/model evidence first
SIM: CPIN READY vs CPIN-context ERROR
registration: evaluate CEREG/CGREG/CREG/C5GREG independently of CSQ
WAN: PPP/PDP/IP only after prior evidence
```

A layer may be `Unknown` if evidence is insufficient; do not force an error.

- [ ] **Step 4: Keep `diagnose()` as a compatibility summary**

Map the strongest actionable layer back to existing `DiagnosisResult`. Preserve `CELLULAR_PPP_IPCP_FAILED` and `WAN_NORMAL` behavior.

- [ ] **Step 5: Run diagnosis tests**

```cmd
ctest --test-dir out\build\debug -C Debug -R "test_diagnosisengine|test_loganalyzer" --output-on-failure
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add diagnostic/DiagnosisEngine.* tests/test_diagnosisengine.cpp
git commit -m "feat: add layered cellular diagnosis"
```

---

### Task 4: Expose TCP payload and richer packet metadata

**Files:**
- Modify: `capture/PcapTypes.h`
- Modify: `capture/PacketParser.cpp`
- Modify: `tests/test_packetparser.cpp`

**Interfaces:**
- Extends `ParsedPacket` with:

```cpp
quint16 ipTotalLength = 0;
quint8 tcpHeaderLength = 0;
quint32 tcpPayloadLength = 0;
QByteArray payload;
```

- `payload` contains transport payload only, not IP/TCP headers.

- [ ] **Step 1: Add a failing TCP-payload parser test**

Construct a minimal Ethernet+IPv4+TCP record with a 6-byte payload `{0x68,0x04,0x07,0,0,0}` and assert:

```cpp
QCOMPARE(p.ipTotalLength, quint16(46));
QCOMPARE(p.tcpHeaderLength, quint8(20));
QCOMPARE(p.tcpPayloadLength, quint32(6));
QCOMPARE(p.payload.toHex(), QByteArray("680407000000"));
```

- [ ] **Step 2: Run `test_packetparser` and observe failure**

- [ ] **Step 3: Implement bounded payload extraction**

Use IPv4 IHL, total length, TCP data offset, and captured bytes. Never read beyond `PcapRecord::data`; if snaplen truncates the packet, payload is the captured subset and `tcpPayloadLength` reports captured transport payload bytes.

- [ ] **Step 4: Re-run parser tests**

Expected: PASS for Ethernet/SLL/RAW existing tests and new payload case.

- [ ] **Step 5: Commit**

```bash
git add capture/PcapTypes.h capture/PacketParser.cpp tests/test_packetparser.cpp
git commit -m "feat: expose TCP payload for protocol analysis"
```

---

### Task 5: Add master/terminal channel analyzer and safe Ping helpers

**Files:**
- Create: `diagnostic/ConnectivityProbe.h`
- Create: `diagnostic/ConnectivityProbe.cpp`
- Create: `diagnostic/ChannelAnalyzer.h`
- Create: `diagnostic/ChannelAnalyzer.cpp`
- Create: `tests/test_connectivityprobe.cpp`
- Create: `tests/test_channelanalyzer.cpp`
- Modify: `tests/CMakeLists.txt`
- Modify: `CMakeLists.txt`

**Interfaces:**

`ConnectivityProbe`:

```cpp
struct PingResult {
    bool validOutput=false;
    bool reachable=false;
    int transmitted=-1;
    int received=-1;
    QStringList evidence;
};

class ConnectivityProbe {
public:
    static bool isValidIpv4(const QString& ip);
    static QString buildPingCommand(const QString& ip, int count=3);
    static PingResult parsePingOutput(const QString& output);
};
```

`ChannelAnalyzer`:

```cpp
struct ChannelCriteria {
    QString peerIp;
    quint16 peerPort=0;
    bool requirePeerPort=false;
};

struct ChannelEvidence {
    quint64 packets=0;
    quint64 syn=0;
    quint64 synAck=0;
    quint64 ack=0;
    quint64 pshAck=0;
    quint64 rst=0;
    quint64 fin=0;
    quint64 payloadPackets=0;
    quint64 payloadBytes=0;
    quint64 icmp140=0;
    bool handshakeComplete=false;
};

class ChannelAnalyzer {
public:
    explicit ChannelAnalyzer(ChannelCriteria criteria={});
    void consume(const ParsedPacket& packet);
    ChannelEvidence evidence() const;
    void reset();
};
```

- [ ] **Step 1: Write failing Ping tests**

Cover BusyBox-style success, 100% loss, and invalid IPv4. Assert command is exactly safe input, e.g. `ping -c 3 192.168.3.102`.

- [ ] **Step 2: Write failing channel tests**

Feed SYN, reverse SYN-ACK, ACK, PSH+ACK and assert `handshakeComplete` and payload counters. Also test only-SYN and RST.

- [ ] **Step 3: Run both new tests and observe missing source/API failures**

- [ ] **Step 4: Implement `ConnectivityProbe` with `QHostAddress` validation**

Return empty command for invalid input; callers must refuse execution.

- [ ] **Step 5: Implement `ChannelAnalyzer` using direction-normalized flow keys**

Only count packets matching `peerIp`; enforce peer port when requested.

- [ ] **Step 6: Add sources and tests to CMake**

- [ ] **Step 7: Run tests**

```cmd
ctest --test-dir out\build\debug -C Debug -R "test_connectivityprobe|test_channelanalyzer|test_packetanalyzer" --output-on-failure
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add diagnostic/ConnectivityProbe.* diagnostic/ChannelAnalyzer.* tests/test_connectivityprobe.cpp tests/test_channelanalyzer.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: add safe reachability and channel evidence analyzers"
```

---

### Task 6: Add IEC104 parser

**Files:**
- Create: `protocol/ProtocolDiagnosis.h`
- Create: `protocol/Iec104Analyzer.h`
- Create: `protocol/Iec104Analyzer.cpp`
- Create: `tests/test_iec104analyzer.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**

```cpp
enum class Iec104FrameKind { Invalid, I, S, U };
enum class Iec104UFunction { None, StartDtAct, StartDtCon, StopDtAct, StopDtCon, TestFrAct, TestFrCon };

struct Iec104Frame {
    bool valid=false;
    QString error;
    Iec104FrameKind kind=Iec104FrameKind::Invalid;
    Iec104UFunction uFunction=Iec104UFunction::None;
    quint16 sendSequence=0;
    quint16 receiveSequence=0;
    int typeId=-1;
    int cot=-1;
    int commonAddress=-1;
    QByteArray raw;
};

class Iec104Analyzer {
public:
    static QList<Iec104Frame> parseStream(const QByteArray& payload);
};
```

- [ ] **Step 1: Write tests for U, I, S, and invalid length frames**

Use exact byte fixtures:

```text
STARTDT act: 68 04 07 00 00 00
STARTDT con: 68 04 0B 00 00 00
TESTFR act:  68 04 43 00 00 00
TESTFR con:  68 04 83 00 00 00
```

Add one synthetic I-frame carrying a minimal ASDU and one S-frame.

- [ ] **Step 2: Run and observe missing parser failure**

- [ ] **Step 3: Implement APDU framing and control-field classification**

Reject `0x68` frames where declared length exceeds available bytes; `parseStream` may return an invalid frame for malformed data and continue only when a safe next boundary is available.

- [ ] **Step 4: Parse basic ASDU fields for I frames**

Only populate Type ID/COT/CA when enough bytes are present.

- [ ] **Step 5: Run `test_iec104analyzer`**

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add protocol/ProtocolDiagnosis.h protocol/Iec104Analyzer.* tests/test_iec104analyzer.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: parse IEC104 APDUs"
```

---

### Task 7: Add IEC101 parser

**Files:**
- Create: `protocol/Iec101Analyzer.h`
- Create: `protocol/Iec101Analyzer.cpp`
- Create: `tests/test_iec101analyzer.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**

```cpp
enum class Iec101FrameKind { Invalid, Fixed, Variable };

struct Iec101Frame {
    bool valid=false;
    QString error;
    Iec101FrameKind kind=Iec101FrameKind::Invalid;
    quint8 control=0;
    int typeId=-1;
    int cot=-1;
    int commonAddress=-1;
    QByteArray raw;
};

class Iec101Analyzer {
public:
    static QList<Iec101Frame> parseStream(const QByteArray& bytes, int linkAddressLength=1);
};
```

- [ ] **Step 1: Write fixed/variable/checksum/length tests**

Include one valid fixed frame `10 C L CS 16` and one valid variable frame `68 L L 68 ... CS 16`; calculate checksum in the test fixture from control through user data.

- [ ] **Step 2: Run and observe missing parser failure**

- [ ] **Step 3: Implement framing and checksum validation**

Validate both repeated length bytes and trailing `0x16`.

- [ ] **Step 4: Parse only fields supported by available configuration**

With `linkAddressLength=1`, populate control; parse ASDU basic fields only when payload contains enough bytes. Never guess alternate link-address sizes.

- [ ] **Step 5: Run `test_iec101analyzer`**

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add protocol/Iec101Analyzer.* tests/test_iec101analyzer.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: parse IEC101 frames"
```

---

### Task 8: Add State Grid security/encryption frame and sequence analyzer

**Files:**
- Create: `protocol/GridFrameTypes.h`
- Create: `protocol/GridSecurityAnalyzer.h`
- Create: `protocol/GridSecurityAnalyzer.cpp`
- Create: `tests/test_gridsecurityanalyzer.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**

```cpp
enum class GridDirection { Unknown, MasterToModule, ModuleToTerminal, TerminalToModule, ModuleToMaster };

struct GridSecurityFrame {
    bool valid=false;
    QString error;
    GridDirection direction=GridDirection::Unknown;
    quint8 command=0;
    QByteArray raw;
};

struct GridSecurityEvidence {
    quint64 totalFrames=0;
    QHash<int,quint64> commandCounts;
    bool auth8020To8023Complete=false;
    bool sequence5051Seen=false;
    bool sequence5253Seen=false;
    bool sequence5455Seen=false;
    bool sequence6061Seen=false;
    bool repeated56Without5051=false;
    QStringList evidence;
};

class GridSecurityAnalyzer {
public:
    static GridSecurityFrame parseHexLogLine(const QString& line);
    void consume(const GridSecurityFrame& frame);
    GridSecurityEvidence evidence() const;
    void reset();
};
```

- [ ] **Step 1: Add failing normal-sequence tests from compact fixtures**

Assert the fixture produces complete `80 20/21/22/23` and paired 50/51 etc. Sequence matching must consider direction order, not merely command presence.

- [ ] **Step 2: Add failing repeated-56 baseline-deviation test**

Fixture contains repeated master-to-module command `0x56`, no matching baseline `50→51` in the same observation window. Assert `repeated56Without5051 == true` only when count threshold is at least 3.

- [ ] **Step 3: Run and observe failure**

- [ ] **Step 4: Implement conservative EB...D7 framing**

Validate start/end and length only to the extent demonstrated by fixtures. If the exact length semantics are ambiguous, mark length as unverified rather than inventing a formula.

- [ ] **Step 5: Implement direction-aware reference state machine**

Treat 80xx and 50/51/etc as *sample-derived reference sequences*. Evidence strings must say “正常样本基线” rather than “协议标准规定”.

- [ ] **Step 6: Run grid tests**

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add protocol/GridFrameTypes.h protocol/GridSecurityAnalyzer.* tests/test_gridsecurityanalyzer.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: analyze State Grid security exchange sequences"
```

---

### Task 9: Build protocol diagnosis composition without pretending to decrypt

**Files:**
- Create: `protocol/ProtocolDiagnosis.cpp`
- Create: `tests/test_protocoldiagnosis.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**

Extend `protocol/ProtocolDiagnosis.h`:

```cpp
enum class BusinessProtocol { Unknown, Iec101, Iec104, GridEncrypted101, GridEncrypted104 };

struct ProtocolEvidence {
    BusinessProtocol protocol=BusinessProtocol::Unknown;
    bool encryptedContentVisible=false;
    QStringList evidence;
    QList<LayerDiagnosis> layers;
};

class ProtocolDiagnosis {
public:
    static ProtocolEvidence analyzeTcpPayload(const QByteArray& payload);
    static ProtocolEvidence analyzeSerialBytes(const QByteArray& bytes);
};
```

- [ ] **Step 1: Write protocol classification tests**

Cases:

- raw STARTDT → IEC104.
- valid IEC101 fixed/variable frame → IEC101.
- EB...D7 security frame with no visible inner IEC payload → security evidence present, business protocol stays Unknown unless fixture explicitly proves 101/104.

- [ ] **Step 2: Run and observe failure**

- [ ] **Step 3: Compose analyzers conservatively**

Do not label encrypted payload as IEC104 merely because configured port is 2404. Port may be supporting context in later UI/report code, not a decoder truth source.

- [ ] **Step 4: Add no-decryption assertion**

A grid encrypted fixture must result in `encryptedContentVisible == false`; conclusion must explicitly say content cannot be decoded without keys/cleartext.

- [ ] **Step 5: Run tests**

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add protocol/ProtocolDiagnosis.* tests/test_protocoldiagnosis.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: compose conservative 101 104 and encrypted diagnostics"
```

---

### Task 10: Add field-diagnostic online command orchestration

**Files:**
- Create: `diagnostic/FieldDiagnosticController.h`
- Create: `diagnostic/FieldDiagnosticController.cpp`
- Create: `tests/test_fielddiagnosticcontroller.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`
- Modify: `diagnostic/DiagnosticController.cpp`

**Interfaces:**

```cpp
enum class TerminalTransport { Ethernet, Serial };

struct FieldDiagnosticConfig {
    QString masterIp;
    quint16 masterPort=2404;
    TerminalTransport terminalTransport=TerminalTransport::Ethernet;
    QString terminalIp;
};

class FieldDiagnosticController : public QObject {
    Q_OBJECT
public:
    explicit FieldDiagnosticController(TelnetClient* control, QObject* parent=nullptr);
    void setConfig(const FieldDiagnosticConfig& config);
    void pingMaster();
    void pingTerminal();
    static QString buildMasterFilter(const FieldDiagnosticConfig& config);
    static QString buildTerminalFilter(const FieldDiagnosticConfig& config);
signals:
    void pingFinished(const QString& target, const PingResult& result);
    void failed(const QString& reason);
};
```

- [ ] **Step 1: Write command/filter construction tests**

Assert:

```cpp
QCOMPARE(FieldDiagnosticController::buildMasterFilter({"90.15.80.82",2404,...}),
         QString("host 90.15.80.82 and port 2404"));
QCOMPARE(FieldDiagnosticController::buildTerminalFilter({...Ethernet,"192.168.3.102"}),
         QString("host 192.168.3.102"));
```

Serial terminal mode must return an empty terminal BPF and refuse `pingTerminal()`.

- [ ] **Step 2: Run and observe failure**

- [ ] **Step 3: Implement config validation and one-command-at-a-time execution**

Use the existing `TelnetClient::executeCommand`; do not change Telnet protocol internals.

- [ ] **Step 4: Remove automatic NVRAM mutation from base diagnosis**

Current `DiagnosticController::startDiagnosis()` executes `nvram set debuglog_enable=3` and commits. Change the automatic command list to read-only collection. A separate future UI action may enable detailed logs explicitly.

Add a test or source-level assertion in `test_fielddiagnosticcontroller` that the automatic command list/API does not expose `nvram set`.

- [ ] **Step 5: Run controller and existing diagnostic tests**

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add diagnostic/FieldDiagnosticController.* diagnostic/DiagnosticController.cpp tests/test_fielddiagnosticcontroller.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: orchestrate safe field probes without nvram mutation"
```

---

### Task 11: Update capture controllers for master and br0 terminal capture

**Files:**
- Modify: `capture/PacketCaptureController.h`
- Modify: `capture/PacketCaptureController.cpp`
- Modify: `tests/test_packetanalyzer.cpp`
- Modify: `tests/test_fielddiagnosticcontroller.cpp`

**Interfaces:**
- Reuses: `PacketCaptureController::start(iface, filter)`.
- Adds no new capture transport.
- Field behavior:
  - master capture interface = diagnosed/user WAN interface.
  - Ethernet terminal capture interface = literal `br0`, filter from `buildTerminalFilter()`.

- [ ] **Step 1: Add a test for exact tcpdump command construction**

Assert the existing command builder accepts:

```text
iface=br0
filter=host 192.168.3.102
```

and produces a command containing `tcpdump -i br0 -U -s 0 -w -` plus the filter, without router-side output file paths.

- [ ] **Step 2: Run capture tests**

- [ ] **Step 3: If necessary, tighten filter quoting/validation without changing stream format**

Only permit filters produced from validated IP/port fields in automatic field diagnosis. Keep manual BPF field behavior unchanged as an explicit advanced input.

- [ ] **Step 4: Run PCAP regression suite**

```cmd
ctest --test-dir out\build\debug -C Debug -R "test_pcapstreamreader|test_packetparser|test_packetanalyzer|test_offlinepcapcontroller" --output-on-failure
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add capture/PacketCaptureController.* tests/test_packetanalyzer.cpp tests/test_fielddiagnosticcontroller.cpp
git commit -m "test: verify master and br0 streaming capture commands"
```

---

### Task 12: Integrate default admin credentials and field controls into the Qt UI

**Files:**
- Modify: `MainWindow.ui`
- Modify: `MainWindow.h`
- Modify: `MainWindow.cpp`

**Interfaces:**
- New widgets with stable object names:
  - `editMasterIp`
  - `spinMasterPort`
  - `comboTerminalTransport`
  - `editTerminalIp`
  - `btnPingMaster`
  - `btnPingTerminal`
  - `btnCaptureMaster`
  - `btnCaptureTerminal`
- `editUser` default text `admin`.
- `editPassword` default text `admin`.

- [ ] **Step 1: Update UI defaults and add field-diagnostic controls**

`comboTerminalTransport` items exactly:

```text
网口
串口
```

`spinMasterPort` defaults to 2404.

- [ ] **Step 2: Implement mode switching**

When serial is selected:

```cpp
ui->editTerminalIp->setEnabled(false);
ui->btnPingTerminal->setEnabled(false);
ui->btnCaptureTerminal->setEnabled(false);
```

Show a status/tooltip that serial mode uses DTS/systemlog evidence and does not assume `/dev/ttyUSB*`.

- [ ] **Step 3: Wire master Ping and capture**

Master capture calls existing `m_capCtrl->start(currentWanIface, masterFilter)` after validating interface/IP/port.

- [ ] **Step 4: Wire terminal Ethernet Ping and capture**

Terminal capture always calls:

```cpp
m_capCtrl->start(QStringLiteral("br0"), terminalFilter);
```

- [ ] **Step 5: Keep manual capture and offline analysis intact**

Do not remove existing WAN interface/BPF/manual capture controls.

- [ ] **Step 6: Build only the GUI target**

```cmd
cmake --build out\build\debug --config Debug --target WanDiagTool
```

Expected: compile/link success.

- [ ] **Step 7: Commit**

```bash
git add MainWindow.ui MainWindow.h MainWindow.cpp
git commit -m "feat: add master and terminal field diagnosis controls"
```

---

### Task 13: Add layered report export and protocol evidence rendering

**Files:**
- Modify: `report/ReportExporter.h`
- Modify: `report/ReportExporter.cpp`
- Create: `tests/test_reportexporter.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`
- Modify: `MainWindow.cpp`

**Interfaces:**

Add:

```cpp
static QString buildFieldReport(const WanStatus& wan,
                                const FieldDiagnosisReport& field,
                                const ProtocolEvidence& protocol);
```

- [ ] **Step 1: Write failing report-format test**

Assert report contains these ordered section titles:

```text
[1] 蜂窝模组/AT
[2] SIM卡
[3] 蜂窝网络注册
[4] WAN/IP
[5] 主站与终端链路
[6] 业务数据（普通IEC101/104或国网加密101/104）
```

Also assert Unknown/NotTested renders as “未知/未测试”, not “异常”.

- [ ] **Step 2: Run and observe missing API failure**

- [ ] **Step 3: Implement text rendering from structured evidence only**

Do not re-parse raw logs in ReportExporter.

- [ ] **Step 4: Render baseline-deviation wording conservatively**

Repeated 0x56 case must include “与当前正常样本基线不一致”; it must not say “0x56 是非法命令”.

- [ ] **Step 5: Run test**

Expected: PASS.

- [ ] **Step 6: Connect MainWindow diagnosis view/save path to field report when available**

Keep legacy report fallback for offline v1.1 fixtures.

- [ ] **Step 7: Commit**

```bash
git add report/ReportExporter.* tests/test_reportexporter.cpp MainWindow.cpp CMakeLists.txt tests/CMakeLists.txt
git commit -m "feat: export seven-layer field diagnosis reports"
```

---

### Task 14: End-to-end regression, offline fixtures, and documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/TESTING.md`
- Modify: `samples/` only if new anonymized sample files are needed

**Interfaces:**
- No new production APIs.

- [ ] **Step 1: Run the complete test suite**

```cmd
cmake --build out\build\debug --config Debug
ctest --test-dir out\build\debug -C Debug --output-on-failure
```

Expected: every test passes.

- [ ] **Step 2: Run offline smoke tests in the GUI**

Verify:

1. existing demo WAN log imports.
2. SIM-not-detected fixture reports module normal/AT responsive + SIM error.
3. registration-failed fixture reports SIM normal + registration error.
4. normal cellular/DTS fixture reports valid WAN and actual south TCP connection.
5. existing demo PCAP still imports/replays.

- [ ] **Step 3: Verify field controls without a device**

Check default UI values:

```text
用户名：admin
密码：admin
主站端口：2404
终端方式：网口
```

Switch to serial and confirm terminal IP Ping/br0 capture controls disable.

- [ ] **Step 4: Document the limits explicitly**

README must state:

- serial active-device probing is not implemented until real terminal serial mapping/logs are supplied.
- encrypted payload is not decrypted without keys.
- 80xx/50xx/56 comparisons are current-sample baselines, not asserted protocol-standard semantics.
- automatic diagnostics do not modify NVRAM.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/TESTING.md samples
git commit -m "docs: document v1.2 field diagnosis workflow and limits"
```

---

## Final Verification Checklist

- [ ] Build succeeds with VS2022 x64 + Qt 6.8.3 MSVC2022_64.
- [ ] All CTest tests pass in Debug.
- [ ] Existing v1.1 offline import/replay behavior is unchanged.
- [ ] No production code treats `/dev/ttyUSB*` as the terminal serial default.
- [ ] `DiagnosticController::startDiagnosis()` contains no automatic `nvram set` or `nvram commit` mutation.
- [ ] WAN capture remains binary PCAP streamed from stdout.
- [ ] Terminal Ethernet capture is `br0` + validated `host <terminalIP>`.
- [ ] SIM-not-detected and registration-failed fixtures produce different root-cause layers.
- [ ] Valid WAN IP is not invalidated by `attach_check: status=0` alone.
- [ ] Grid security baseline deviation does not masquerade as TCP failure.
- [ ] IEC101 and IEC104 parsers are separate from Grid security framing.
- [ ] Encrypted data without keys is reported as opaque rather than “decoded”.
