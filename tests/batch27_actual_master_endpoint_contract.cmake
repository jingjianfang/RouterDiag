set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
file(READ "${ROOT}/diagnostic/FieldDiagnosticController.cpp" FD)
file(READ "${ROOT}/diagnostic/ChannelAnalyzer.h" CAH)
file(READ "${ROOT}/diagnostic/ChannelAnalyzer.cpp" CAC)
file(READ "${ROOT}/MainWindow.cpp" MW)
file(READ "${ROOT}/tests/test_channelanalyzer.cpp" TESTCA)

function(req text needle msg)
  string(FIND "${text}" "${needle}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "${msg}: missing [${needle}]")
  endif()
endfunction()

# Configured master address is advisory for TCP when master is a client.
req("${FD}" "tcp port %2" "master TCP capture must be business-port based")
req("${FD}" "configured master IP is an expected/reference address" "code must document advisory configured IP")

# Real endpoint discovery and direction classification are centralized/testable.
req("${CAH}" "packetFromActualPeer" "master payload direction helper must be declared")
req("${CAC}" "ChannelAnalyzer::packetFromActualPeer" "master payload direction helper must be implemented")
req("${MW}" "ChannelAnalyzer::packetFromActualPeer" "both workflow capture paths must use common real-peer direction logic")
req("${MW}" "实际主站连接源IP与配置主站IP不一致" "mismatch must be surfaced as a hint")
req("${MW}" "该差异仅提示，不直接判故障" "mismatch must not be treated as failure")

# Serial terminal diagnosis must preserve downstream payload evidence.
req("${MW}" "主站已有业务数据到达WAN" "serial terminal no-response diagnosis must exist")
req("${MW}" "主站下发数据%1" "downstream payload must be printed")
req("${TESTCA}" "discoversActualMasterClientBehindDifferentConfiguredIp" "unit regression for actual client endpoint must exist")
req("${TESTCA}" "classifiesMasterClientPayloadDirectionByActualPeer" "unit regression for real-peer direction must exist")

message(STATUS "Batch27 actual-master endpoint contract passed")
