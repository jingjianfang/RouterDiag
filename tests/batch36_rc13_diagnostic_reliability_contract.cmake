set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
function(require_contains path needle)
  file(READ "${ROOT}/${path}" TEXT)
  string(FIND "${TEXT}" "${needle}" POS)
  if(POS EQUAL -1)
    message(FATAL_ERROR "Batch36: ${path} missing: ${needle}")
  endif()
endfunction()
function(require_not_contains path needle)
  file(READ "${ROOT}/${path}" TEXT)
  string(FIND "${TEXT}" "${needle}" POS)
  if(NOT POS EQUAL -1)
    message(FATAL_ERROR "Batch36: ${path} must not contain: ${needle}")
  endif()
endfunction()

# WAN 0.0.0.0 must never be treated as usable/current WAN success.
require_contains("diagnostic/ConnectivityProbe.h" "isUsableWanIpv4")
require_contains("tests/test_connectivityprobe.cpp" "0.0.0.0")
require_contains("tests/test_diagnosisengine.cpp" "zeroWanIpIsNotWanNormal")
require_not_contains("diagnostic/LogAnalyzer.cpp" "s.wanIp=s.backupWanIp")

# RC13 diagnostic reliability structure.
require_contains("diagnostic/AtStatusParser.h" "fieldQuoted")
require_contains("diagnostic/AtStatusParser.h" "preferredRegistration")
require_contains("diagnostic/DiagnosticTypes.h" "moduleProbeCompleted")
require_contains("diagnostic/ChannelAnalyzer.h" "actualPeerSessions")
require_contains("diagnostic/DualCaptureCorrelator.h" "streamMatchedPackets")
require_contains("protocol/ProtocolDiagnosis.h" "responseExpected")

# RC13 quick-command and responsive workspace structure (Batch48 removed the redundant view selector).
require_contains("ui/RemoteToolDialog.cpp" "搜索名称 / 命令 / 备注")
require_contains("ui/RemoteToolDialog.cpp" "iptables -t nat -L -n -v")
require_contains("MainWindow.cpp" "setupRc13Workspace()")
require_contains("tests/test_mainwindowui.cpp" "workspaceSelectorIsRemoved")


# Batch48 keeps the module card status simple; model/firmware remain evidence in tooltip/report.
require_contains("MainWindow.cpp" "厂商：%1")
require_contains("MainWindow.cpp" "固件：%1")
require_contains("diagnostic/DiagnosisEngine.cpp" "固件版本")

message(STATUS "Batch36 RC13 diagnostic reliability contract passed")
