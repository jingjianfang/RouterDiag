set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
file(READ "${ROOT}/MainWindow.ui" UI)
file(READ "${ROOT}/MainWindow.cpp" MAINCPP)
file(READ "${ROOT}/MainWindow.h" MAINH)
file(READ "${ROOT}/ui/RemoteToolDialog.cpp" REMOTECPP)
file(READ "${ROOT}/ui/RemoteToolDialog.h" REMOTEH)

foreach(token IN ITEMS
  "<width>800</width>"
  "<height>520</height>"
  "QScrollArea"
  "mainScrollArea"
  "responsiveLayoutMode"
  "reflowResponsiveLayout"
  "resizeEvent")
  string(FIND "${UI}${MAINCPP}${MAINH}" "${token}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "Batch16 responsive UI contract missing: ${token}")
  endif()
endforeach()

foreach(token IN ITEMS
  "tail /tmp/.systemlog -f"
  "setInterval(50)"
  "flushPendingModuleLog"
  "labelModuleLogRuntime"
  "模块日志实时读取"
  "m_moduleLogLineCount"
  "Do not synthesize line breaks between TCP chunks")
  string(FIND "${REMOTECPP}${REMOTEH}" "${token}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "Batch16 live module log contract missing: ${token}")
  endif()
endforeach()

message(STATUS "Batch16 contract OK")
