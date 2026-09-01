cmake_minimum_required(VERSION 3.16)

get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
file(READ "${ROOT}/diagnostic/ChannelAnalyzer.cpp" CHANNEL_SRC)
file(READ "${ROOT}/MainWindow.cpp" MAINWINDOW_SRC)
file(READ "${ROOT}/diagnostic/FieldWorkflowController.cpp" WORKFLOW_SRC)

function(require_contains haystack needle message_text)
    string(FIND "${${haystack}}" "${needle}" pos)
    if(pos EQUAL -1)
        message(FATAL_ERROR "${message_text}: missing '${needle}'")
    endif()
endfunction()

function(require_not_contains haystack needle message_text)
    string(FIND "${${haystack}}" "${needle}" pos)
    if(NOT pos EQUAL -1)
        message(FATAL_ERROR "${message_text}: found forbidden '${needle}'")
    endif()
endfunction()

# Pure Echo timeout is not proof that a master station is unreachable: the site may block ICMP.
require_contains(CHANNEL_SRC "主站可能禁Ping" "Master no-Echo diagnosis must explicitly allow ICMP-disabled sites")
require_contains(CHANNEL_SRC "d.state=LayerState::Unknown" "Master pure no-Echo result must remain inconclusive without TCP evidence")

# Explicit routing failures must still be distinguishable from an ICMP-disabled peer.
require_contains(CHANNEL_SRC "NetworkUnreachable" "Master diagnosis must preserve explicit route failure handling")
require_contains(CHANNEL_SRC "DestinationHostUnreachable" "Master diagnosis must preserve explicit destination-unreachable handling")

# The UI must not merge 'no Echo Reply' with 'unreachable'.
require_contains(MAINWINDOW_SRC "未收到ICMP应答" "Ping result UI must describe a no-Echo result neutrally")
require_not_contains(MAINWINDOW_SRC "未应答/不可达" "Ping result UI must not conflate no Echo with unreachable")

# One-click diagnosis must continue into master TCP capture after Ping completes.
require_contains(WORKFLOW_SRC "moveTo(FieldWorkflowStep::CaptureMaster,FieldWorkflowAction::CaptureMaster)" "Master Ping completion must continue to TCP capture")

message(STATUS "Batch21 master Ping policy contract passed")
