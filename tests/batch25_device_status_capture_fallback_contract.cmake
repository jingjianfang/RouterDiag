set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
file(READ "${ROOT}/MainWindow.cpp" MW)
file(READ "${ROOT}/diagnostic/DeviceDiscoveryController.cpp" DDCPP)
file(READ "${ROOT}/diagnostic/DeviceDiscoveryController.h" DDH)
file(READ "${ROOT}/diagnostic/LogAnalyzer.cpp" LOGCPP)
file(READ "${ROOT}/capture/PacketCaptureController.cpp" CAPCPP)
file(READ "${ROOT}/capture/PacketCaptureController.h" CAPH)

function(require_contains text needle message)
  string(FIND "${text}" "${needle}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "${message}: missing [${needle}]")
  endif()
endfunction()

# WAN status card must prefer the interface verified by live device discovery and reject command echoes.
require_contains("${MW}" "const QString wanIface=!m_discoveredWanIfname.isEmpty()?m_discoveredWanIfname:m_lastStatus.wanIfname" "WAN card must prefer discovered interface")
require_contains("${LOGCPP}" "isUsableWanInterfaceName" "log-derived WAN interface must be validated")
require_contains("${LOGCPP}" "nvram get wan_ifname" "WAN parser must explicitly guard command echo")

# Once an AT port is confirmed, discovery must actively query SIM and registration state.
foreach(cmd "AT+CPIN?" "AT+CEREG?" "AT+CGREG?" "AT+CREG?" "AT+C5GREG?")
  require_contains("${DDCPP}" "${cmd}" "device discovery must actively query ${cmd}")
endforeach()
require_contains("${DDH}" "QString simStatus" "discovery result must carry SIM state")
require_contains("${DDH}" "QString cereg" "discovery result must carry registration state")
require_contains("${MW}" "result.simStatus" "discovery SIM state must be merged into UI status")
require_contains("${MW}" "result.cereg" "discovery registration state must be merged into UI status")

# Network capture: if binary PCAP header never arrives and tcpdump reports no real error,
# automatically fall back to a text tcpdump capture instead of failing immediately.
require_contains("${CAPH}" "beginTextFallbackCapture" "capture controller must expose internal text fallback path")
require_contains("${CAPH}" "m_textFallbackActive" "capture controller must track text fallback state")
require_contains("${CAPCPP}" "自动切换到 tcpdump -xx 文本抓包" "user must be told when fallback activates")
require_contains("${CAPCPP}" "beginTextFallbackCapture();" "empty binary-start error must enter text fallback")

message(STATUS "Batch25 device status + capture fallback contract passed")
