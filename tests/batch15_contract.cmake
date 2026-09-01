set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
file(READ "${ROOT}/MainWindow.ui" UI)
file(READ "${ROOT}/MainWindow.cpp" MAINCPP)
file(READ "${ROOT}/capture/PacketCaptureController.cpp" CAPCPP)
file(READ "${ROOT}/ui/RemoteToolDialog.cpp" REMOTECPP)

foreach(token IN ITEMS
  "checkFollowLatestPacket"
  "txtPacketHex"
  "txtRealtimeTcpSessions"
  "txtPacketBusiness"
  "labelCaptureState")
  string(FIND "${UI}" "${token}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "Batch15 UI contract missing: ${token}")
  endif()
endforeach()

foreach(token IN ITEMS
  "lastCommandExitCode()"
  "(exit 127)"
  "(exit 2)"
  "/tmp/wandiag_tcpdump.err")
  string(FIND "${CAPCPP}" "${token}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "Capture preflight contract missing: ${token}")
  endif()
endforeach()
foreach(token IN ITEMS "__WANDIAG_CAPTURE_OK__" "__WANDIAG_NO_TCPDUMP__" "__WANDIAG_NO_IFACE__")
  string(FIND "${CAPCPP}" "${token}" pos)
  if(NOT pos EQUAL -1)
    message(FATAL_ERROR "Capture preflight must not rely on echoed text marker: ${token}")
  endif()
endforeach()

foreach(token IN ITEMS
  "tableQuickCommands"
  "备注"
  "commandQuickCommandSelected"
  "nvram get debuglog_enable"
  "nvram set debuglog_enable=1"
  "nvram set syslogd_enable=3"
  "nvram commit"
  "tail /tmp/.systemlog -f"
  "RSRP"
  "SINR")
  string(FIND "${REMOTECPP}" "${token}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "Remote tool contract missing: ${token}")
  endif()
endforeach()

string(FIND "${MAINCPP}" "m_packetChannelAnalyzer.consume" pos)
if(pos EQUAL -1)
  message(FATAL_ERROR "Realtime TCP analyzer is not connected to packet stream")
endif()
message(STATUS "Batch15 contract OK")
