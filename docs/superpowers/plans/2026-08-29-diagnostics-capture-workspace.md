# Diagnostics Capture Workspace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved log, module, diagnostic-layer, real-time multi-capture, detachable UI, shortcut import/export and endpoint-role improvements.

**Architecture:** Add focused incremental parser and detachable-tab helpers; evolve capture control into session-capable objects while preserving the existing single-session MainWindow integration. Keep internal diagnosis six-layer and add presentation aggregation plus endpoint-role evidence.

**Tech Stack:** C++17, Qt 5/6 Core/Network/Widgets/SerialPort/Test, CMake.

**Spec:** `docs/superpowers/specs/2026-08-29-diagnostics-capture-workspace-design.md`

## Global Constraints
- Windows + VS2022 + Qt 6.8.3 msvc2022_64 remains supported.
- Physical router serial transport allows one active capture at a time.
- Existing network Telnet behavior remains backward compatible.
- Builtin quick commands are never overwritten by imports.

---

### Task 1: Router log and module discovery correctness
**Files:** `MainWindow.cpp`, `ui/RemoteToolDialog.*`, `diagnostic/DeviceDiscoveryController.*`, tests.
- [ ] Add failing contract for correct NVRAM values/commit and tagged AT output.
- [ ] Implement state machine for debuglog=1 and syslogd=3/0.
- [ ] Bound AT output and reject shell echo as module model.
- [ ] Run contract.

### Task 2: Four-layer presentation and endpoint roles
**Files:** `diagnostic/FieldDiagnosticController.*`, `diagnostic/ChannelAnalyzer.*`, `MainWindow.*`, `MainWindow.ui`, `report/ReportExporter.*`, tests.
- [ ] Add role/config and aggregation tests.
- [ ] Add UI role selectors and timeout.
- [ ] Aggregate first three internal layers for UI/report.
- [ ] Add actual-master discovery/mismatch/serial-response diagnosis.
- [ ] Run tests/contracts.

### Task 3: Incremental tcpdump text parser
**Files:** `capture/TcpdumpTextStreamParser.*`, `capture/PacketCaptureController.*`, tests, CMake.
- [ ] Add parser test proving packet is emitted before stop.
- [ ] Implement incremental PCAP records and packet signal.
- [ ] Integrate text fallback streaming.
- [ ] Run tests/contracts.

### Task 4: Multi-capture sessions and synchronized one-click captures
**Files:** `capture/CaptureSession.*`, `ui/CaptureSessionWidget.*`, `MainWindow.*`, CMake/tests.
- [ ] Add session construction and `any` preflight contract.
- [ ] Add network parallel sessions / serial active-session guard.
- [ ] Add `+ 新建抓包`, independent filter/interface/storage.
- [ ] Add one-click dual capture and same-interface coalescing.
- [ ] Run contracts.

### Task 5: Detachable tabs
**Files:** `ui/DetachableTabWidget.*`, `MainWindow.cpp`, CMake/tests.
- [ ] Add drag/double-click detach/reattach helper.
- [ ] Replace or upgrade principal/nested tab widgets at runtime.
- [ ] Verify same widget instance reattaches.

### Task 6: Quick command import/export
**Files:** `ui/RemoteToolDialog.*`, tests.
- [ ] Fix builtin names and separate live tail command.
- [ ] Add JSON export all.
- [ ] Add JSON import as custom copies only.
- [ ] Run tests/contracts.

### Task 7: Final regression and packaging
**Files:** tests, README, packaging scripts as needed.
- [ ] Run Batch15+ contracts, XML parse, CMake configure attempt.
- [ ] Diff against baseline for scope.
- [ ] Package source ZIP and patch.
