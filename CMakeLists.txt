cmake_minimum_required(VERSION 3.20)
project(WanDiagTool VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Network Widgets SerialPort)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network Widgets SerialPort)

add_library(wandiag_core
    telnet/TelnetDecoder.cpp
    telnet/TelnetDecoder.h
    telnet/TelnetClient.cpp
    telnet/TelnetClient.h
    diagnostic/DiagnosticTypes.h
    diagnostic/AtStatusParser.cpp
    diagnostic/AtStatusParser.h
    diagnostic/LogAnalyzer.cpp
    diagnostic/LogAnalyzer.h
    diagnostic/NvramSnapshotParser.cpp
    diagnostic/NvramSnapshotParser.h
    diagnostic/DiagnosisEngine.cpp
    diagnostic/DiagnosisEngine.h
    diagnostic/DiagnosticController.cpp
    diagnostic/DiagnosticController.h
    diagnostic/ConnectivityProbe.cpp
    diagnostic/ConnectivityProbe.h
    diagnostic/ChannelAnalyzer.cpp
    diagnostic/ChannelAnalyzer.h
    diagnostic/DualCaptureCorrelator.cpp
    diagnostic/DualCaptureCorrelator.h
    diagnostic/FieldDiagnosticController.cpp
    diagnostic/FieldDiagnosticController.h
    diagnostic/FieldWorkflowController.cpp
    diagnostic/FieldWorkflowController.h
    diagnostic/DeviceDiscoveryController.cpp
    diagnostic/DeviceDiscoveryController.h
    capture/PcapTypes.h
    capture/PcapStreamReader.cpp
    capture/PcapStreamReader.h
    capture/PacketParser.cpp
    capture/PacketParser.h
    capture/TcpStreamReassembler.cpp
    capture/TcpStreamReassembler.h
    capture/PacketAnalyzer.cpp
    capture/PacketAnalyzer.h
    capture/PacketCaptureController.cpp
    capture/PacketCaptureController.h
    capture/OfflinePcapController.cpp
    capture/OfflinePcapController.h
    capture/TcpdumpTextPcapConverter.cpp
    capture/TcpdumpTextPcapConverter.h
    capture/TcpdumpTextStreamParser.cpp
    capture/TcpdumpTextStreamParser.h
    protocol/ProtocolDiagnosis.cpp
    protocol/ProtocolDiagnosis.h
    protocol/Iec104Analyzer.cpp
    protocol/Iec104Analyzer.h
    protocol/Iec104SessionAnalyzer.cpp
    protocol/Iec104SessionAnalyzer.h
    protocol/Iec101Analyzer.cpp
    protocol/Iec101Analyzer.h
    protocol/GridFrameTypes.h
    protocol/GridSecurityAnalyzer.cpp
    protocol/GridSecurityAnalyzer.h
    report/ReportExporter.cpp
    report/ReportExporter.h
)

target_include_directories(wandiag_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(wandiag_core PUBLIC Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network Qt${QT_VERSION_MAJOR}::SerialPort)

add_executable(WanDiagTool
    main.cpp
    MainWindow.cpp
    MainWindow.h
    MainWindow.ui
    ui/RemoteToolDialog.cpp
    ui/RemoteToolDialog.h
    ui/DetachableTabWidget.cpp
    ui/DetachableTabWidget.h
    ui/DetachablePanelManager.cpp
    ui/DetachablePanelManager.h
    ui/CaptureSessionWidget.cpp
    ui/CaptureSessionWidget.h
    resources/app_icon.qrc
)
target_link_libraries(WanDiagTool PRIVATE wandiag_core Qt${QT_VERSION_MAJOR}::Widgets)
if(WIN32)
    target_sources(WanDiagTool PRIVATE resources/app_icon.rc)
    set_target_properties(WanDiagTool PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

include(CTest)
if(BUILD_TESTING)
    find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test)
    add_subdirectory(tests)
endif()
