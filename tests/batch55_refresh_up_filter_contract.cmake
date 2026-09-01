cmake_minimum_required(VERSION 3.16)
get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
file(READ "${ROOT}/MainWindow.cpp" MW)

function(req needle msg)
  string(FIND "${MW}" "${needle}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "Batch55 contract failed: ${msg}: missing [${needle}]")
  endif()
endfunction()

# 手工“刷新接口”收到普通 ifconfig 结果后，也必须显式丢弃非 UP 项；
# 不能只依赖 BusyBox 普通 ifconfig 通常不输出 DOWN 接口这一行为。
req("const auto parsedInterfaces=DeviceDiscoveryParser::parseInterfaces(output);" "manual refresh must parse into a temporary inventory")
req("for(const auto& info:parsedInterfaces){\n            if(!info.up)continue;\n            m_discoveredInterfaces.append(info);" "manual refresh must persist only UP interfaces")
req("ui->tableInterfaces->setRowCount(0);" "manual refresh table must be rebuilt from filtered UP interfaces")
req("QStringLiteral(\"已读取 %1 个 ifconfig UP 接口\")" "refresh status must describe the UP-only inventory")

# 自动检测路径本来就有显式 UP 过滤，继续锁住，避免以后两条路径再次分叉。
req("for(const auto& info:result.interfaces){\n        if(!info.up)continue;" "automatic discovery details must keep explicit UP filtering")

message(STATUS "Batch55 refresh UP-only contract passed")
