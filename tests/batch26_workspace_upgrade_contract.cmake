set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
file(READ "${ROOT}/MainWindow.cpp" MW)
file(READ "${ROOT}/MainWindow.h" MWH)
file(READ "${ROOT}/MainWindow.ui" UI)
file(READ "${ROOT}/diagnostic/DeviceDiscoveryController.cpp" DD)
file(READ "${ROOT}/diagnostic/FieldDiagnosticController.h" FDH)
file(READ "${ROOT}/diagnostic/ChannelAnalyzer.h" CAH)
file(READ "${ROOT}/ui/RemoteToolDialog.cpp" RT)
file(READ "${ROOT}/capture/PacketCaptureController.cpp" PC)
file(READ "${ROOT}/CMakeLists.txt" CMAKE)

function(req text needle msg)
  string(FIND "${text}" "${needle}" p)
  if(p EQUAL -1)
    message(FATAL_ERROR "${msg}: missing [${needle}]")
  endif()
endfunction()

# Correct log configuration.
req("${MW}" "nvram set debuglog_enable=1" "main background log must enable debuglog=1")
req("${MW}" "nvram set syslogd_enable=3" "network Telnet tail must select web/systemlog output")
req("${RT}" "nvram set debuglog_enable=1" "module log tool must enable debuglog=1")
req("${RT}" "nvram set syslogd_enable=3" "module log tool must enable syslogd=3")

# AT output boundaries and model sanitation.
req("${DD}" "__FF_AT_BEGIN__" "AT probe must bracket output")
req("${DD}" "__FF_AT_END__" "AT probe must bracket output")
req("${DD}" "isPlausibleModuleIdentity" "module display must reject shell echo")

# Four presentation layers + endpoint roles.
req("${MWH}" "currentPresentationLayers" "UI must aggregate six internal layers")
req("${FDH}" "EndpointRole" "field config must carry client/server roles")
req("${FDH}" "expectedConnectionSeconds" "field config must carry timeout")
req("${MWH}" "m_actualMasterIps" "actual master endpoints must be tracked separately from configured IP")
req("${MW}" "实际主站连接IP" "report/UI must surface actual master IP")
req("${MW}" "串口终端配置、接线" "serial terminal no-response guidance must exist")

# Incremental text fallback.
req("${CMAKE}" "TcpdumpTextStreamParser.cpp" "incremental tcpdump parser must be built")
req("${PC}" "m_textStreamParser.feed" "text fallback must feed incremental parser")

# Multi-capture and detachable tabs.
req("${CMAKE}" "DetachableTabWidget.cpp" "detachable tab helper must be built")
req("${CMAKE}" "CaptureSessionWidget.cpp" "capture session widget must be built")
req("${MWH}" "m_captureSessions" "MainWindow must own multiple capture sessions")
req("${MW}" "同一时间只能运行 1 个实时抓包" "serial transport must guard concurrent captures")
req("${PC}" "iface==QStringLiteral(\"any\")" "any interface must skip ifconfig preflight")

# Quick command import/export.
req("${RT}" "QStringLiteral(\"查看网口\"),QStringLiteral(\"ifconfig\")" "ifconfig builtin must keep its command with a plain-language name")
req("${RT}" "tail /tmp/.systemlog -f" "live system log must be standalone builtin")
req("${RT}" "exportQuickCommands" "quick commands must export JSON")
req("${RT}" "importQuickCommands" "quick commands must import JSON")

message(STATUS "Batch26 workspace upgrade contract passed")
