# WAN Diag Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a VS2022 + Qt C++ Widgets WAN diagnostic and live PCAP capture tool that streams `tcpdump -w -` over Telnet without writing PCAP files on the router.

**Architecture:** Two independent `QTcpSocket` Telnet clients separate command/control traffic from binary PCAP traffic. The capture path decodes Telnet IAC bytes, incrementally parses Classic PCAP, decodes basic IPv4/TCP/UDP/ICMP packets, updates heuristics/statistics, and optionally writes the exact PCAP byte stream to a local Windows file.

**Tech Stack:** C++17, Qt 5.15.x / Qt 6.x, Qt Widgets, Qt Network, Qt Test, CMake, VS2022/MSVC.

**Spec:** `docs/superpowers/specs/2026-08-28-wan-diag-tool-design.md`

## Global Constraints

- Visual Studio 2022.
- Qt 5.15.x / Qt 6.x.
- C++17.
- No Python dependency.
- No Npcap, WinPcap or libpcap dependency for core functionality.
- Router must not write `.pcap`; capture uses `tcpdump -U -s 0 -w -`.
- First release supports Classic PCAP only, not PCAPNG.
- First release performs basic IPv4/TCP/UDP/ICMP parsing and heuristic anomaly detection.

---

### Task 1: Project scaffold and shared types

**Files:**
- Create: `CMakeLists.txt`, `main.cpp`
- Create: `diagnostic/DiagnosticTypes.h`
- Create: `capture/PcapTypes.h`
- Create: `tests/CMakeLists.txt`, `tests/test_smoke.cpp`

**Interfaces:**
- Produces `WanStatus`, `DiagnosisResult`, `CmeErrorRecord`, `ParsedPacket`, `CaptureStats`, and PCAP link-type/constants used by later tasks.

- [ ] Write a Qt Test smoke test that constructs shared types and checks defaults.
- [ ] Configure CMake with Qt5/Qt6 fallback and `BUILD_TESTING`.
- [ ] Build and run `ctest`; smoke test must pass when Qt is available.
- [ ] Commit scaffold.

### Task 2: Telnet IAC stream decoder

**Files:**
- Create: `telnet/TelnetDecoder.h/.cpp`
- Create: `tests/test_telnetdecoder.cpp`

**Interfaces:**
- Produces `TelnetDecodeResult TelnetDecoder::feed(const QByteArray&)` where result contains `payload` and `replyBytes`.
- Decoder preserves state across fragmented input.

- [ ] Add failing tests for plain bytes, `FF FF`, WILL/WONT/DO/DONT stripping, negotiation reply, and fragmented IAC sequences.
- [ ] Implement minimal state machine.
- [ ] Run tests and verify all decoder cases pass.
- [ ] Commit decoder.

### Task 3: Incremental Classic PCAP reader

**Files:**
- Create: `capture/PcapStreamReader.h/.cpp`
- Create: `tests/test_pcapstreamreader.cpp`

**Interfaces:**
- `appendData(const QByteArray&)`, `reset()`.
- Signals: `globalHeaderReady(PcapGlobalHeaderInfo)`, `packetReady(PcapRecord)`, `streamError(QString)`.
- Exposes exact accepted raw PCAP bytes through `rawBytesAccepted(QByteArray)` for local export.

- [ ] Add failing tests for little-endian microsecond PCAP, fragmented global header, fragmented packet record, big-endian PCAP, nanosecond magic, invalid magic, and oversized `incl_len`.
- [ ] Implement header detection/endian helpers and incremental parser.
- [ ] Run tests and verify all cases pass.
- [ ] Commit PCAP reader.

### Task 4: Packet parser

**Files:**
- Create: `capture/PacketParser.h/.cpp`
- Create: `tests/test_packetparser.cpp`

**Interfaces:**
- `ParsedPacket PacketParser::parse(const PcapRecord&, quint32 linkType)`.
- Supports Ethernet DLT_EN10MB, Linux SLL DLT_LINUX_SLL, and DLT_RAW.

- [ ] Add failing synthetic-packet tests for Ethernet IPv4 TCP, UDP, ICMP, Linux SLL IPv4, RAW IPv4, truncated frames and unsupported link type.
- [ ] Implement bounds-checked network/transport parsing.
- [ ] Run tests.
- [ ] Commit parser.

### Task 5: Packet analyzer

**Files:**
- Create: `capture/PacketAnalyzer.h/.cpp`
- Create: `tests/test_packetanalyzer.cpp`

**Interfaces:**
- `void consume(const ParsedPacket&)`, `CaptureStats stats() const`, `QStringList topConversations(int) const`, `reset()`.

- [ ] Add failing tests for protocol counters, SYN/RST/FIN, ICMP request/reply, duplicate TCP sequence heuristic, SYN-without-response tracking, and conversation ranking.
- [ ] Implement bounded in-memory flow state.
- [ ] Run tests.
- [ ] Commit analyzer.

### Task 6: Log analyzer and fault engine

**Files:**
- Create: `diagnostic/LogAnalyzer.h/.cpp`
- Create: `diagnostic/DiagnosisEngine.h/.cpp`
- Create: `tests/test_loganalyzer.cpp`, `tests/test_diagnosisengine.cpp`
- Copy test fixtures from uploaded logs into `tests/fixtures/`.

**Interfaces:**
- `WanStatus LogAnalyzer::analyze(const QString& text)`.
- `DiagnosisResult DiagnosisEngine::diagnose(const WanStatus&)`.

- [ ] Add failing parser tests for CPIN, CGREG/C5GREG/CREG, CGATT, CSQ, RSRP, APN, WAN IP variants, module info, PPP/LCP/IPCP counts, WAN-not-up and contextual CME errors.
- [ ] Add failing regression tests showing the success sample is not failed by `CME ERROR: 6003`, and the failure sample is classified as cellular PPP/IPCP address negotiation failure.
- [ ] Implement parser and priority engine.
- [ ] Run tests.
- [ ] Commit diagnosis core.

### Task 7: Telnet client

**Files:**
- Create: `telnet/TelnetClient.h/.cpp`
- Create: `tests/test_telnetclient.cpp`

**Interfaces:**
- Async API: `connectToHost`, `disconnectFromHost`, `login`, `executeCommand`, `setMode(TelnetMode)`.
- Signals: `connected`, `loginSucceeded`, `loginFailed`, `commandFinished`, `textReceived`, `binaryReceived`, `errorOccurred`.
- Internally uses `TelnetDecoder` for both control and capture streams.

- [ ] Add local fake-server tests for login prompts, command prompt completion, timeout, and binary IAC decoding.
- [ ] Implement non-blocking state machine using `QTcpSocket` + `QTimer`.
- [ ] Run tests.
- [ ] Commit Telnet client.

### Task 8: WAN diagnostic controller

**Files:**
- Create: `diagnostic/DiagnosticController.h/.cpp`
- Create: `tests/test_diagnosticcontroller.cpp`

**Interfaces:**
- `startDiagnosis()`, `cancel()`.
- Signals progress, `finished(WanStatus, DiagnosisResult, QString reportText)`, `failed(QString)`.

- [ ] Add scripted fake-Telnet tests for preferred commands, fallbacks, timeout continuation, and debuglog restoration only when the original value was successfully read.
- [ ] Implement command sequence and aggregation.
- [ ] Run tests.
- [ ] Commit controller.

### Task 9: Capture controller and local PCAP export

**Files:**
- Create: `capture/PacketCaptureController.h/.cpp`
- Create: `tests/test_packetcapturecontroller.cpp`

**Interfaces:**
- `start(interface, filter)`, `stop()`, `exportBufferedPcap(path)`, `setDirectSavePath(path)`.
- Signals: `packetReady`, `statsUpdated`, `captureStarted`, `captureStopped`, `captureError`.

- [ ] Add tests for exact tcpdump command construction and safe single-quote escaping/rejection policy for filters.
- [ ] Add tests that decoded binary bytes are fed to `PcapStreamReader`, retained in memory when configured, and written unchanged to a PC-local file in direct-save mode.
- [ ] Add stop-strategy tests: `pidof`, `ps` fallback, `kill -2`, final `killall` fallback.
- [ ] Implement controller using separate control/capture Telnet clients.
- [ ] Run tests.
- [ ] Commit capture controller.

### Task 10: Report exporter

**Files:**
- Create: `report/ReportExporter.h/.cpp`
- Create: `tests/test_reportexporter.cpp`

**Interfaces:**
- `QString buildTextReport(const WanStatus&, const DiagnosisResult&)`.
- `bool saveTextReport(path, ...)`, `bool saveJsonReport(path, ...)`.

- [ ] Add deterministic text/JSON tests.
- [ ] Implement exporter with `QJsonDocument`.
- [ ] Run tests.
- [ ] Commit exporter.

### Task 11: Qt Widgets main window

**Files:**
- Create: `MainWindow.h/.cpp/.ui`
- Modify: `main.cpp`, `CMakeLists.txt`

**Interfaces:**
- Connects UI actions to `DiagnosticController` and `PacketCaptureController` only; no packet parsing logic lives in UI.

- [ ] Build UI with connection, diagnosis, capture, packet table and statistics sections.
- [ ] Wire connect/diagnose/start/stop/export/open-directory actions.
- [ ] Keep GUI responsive by relying on async controllers/signals.
- [ ] Build application target successfully with Qt.
- [ ] Commit GUI.

### Task 12: Documentation, fixture regression and release verification

**Files:**
- Create: `README.md`
- Create: `docs/TESTING.md`
- Update: `CMakeLists.txt`

**Interfaces:**
- Documents VS2022 + Qt configure/build steps and router requirements.

- [ ] Run full test suite.
- [ ] Run success/failure log regression tests.
- [ ] Run CMake configure/build on available environment or document if Qt SDK is absent in the execution environment.
- [ ] Verify ZIP contains source, `.ui`, CMake, tests, docs and no generated binaries required to build.
- [ ] Commit docs/release preparation.
