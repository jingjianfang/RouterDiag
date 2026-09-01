set(TEST_TARGETS
    test_atstatusparser
    test_dualcapturecorrelator
    test_iec104sessionanalyzer
    test_telnetdecoder
    test_pcapstreamreader
    test_packetparser
    test_tcpstreamreassembler
    test_packetanalyzer
    test_packetcapturecontroller
    test_loganalyzer
    test_nvramsnapshotparser
    test_diagnosisengine
    test_offlinepcapcontroller
    test_iec104analyzer
    test_iec101analyzer
    test_gridsecurityanalyzer
    test_protocoldiagnosis
    test_reportexporter
    test_connectivityprobe
    test_channelanalyzer
    test_fielddiagnosticcontroller
    test_fieldworkflowcontroller
    test_devicediscovery
    test_tcpdumptextpcapconverter
    test_tcpdumptextstreamparser
)
foreach(t IN LISTS TEST_TARGETS)
    add_executable(${t} ${t}.cpp)
    target_link_libraries(${t} PRIVATE wandiag_core Qt${QT_VERSION_MAJOR}::Test)
    add_test(NAME ${t} COMMAND ${t})
endforeach()

add_executable(test_mainwindowui
    test_mainwindowui.cpp
    ../MainWindow.cpp
    ../MainWindow.h
    ../MainWindow.ui
    ../ui/RemoteToolDialog.cpp
    ../ui/RemoteToolDialog.h
    ../ui/DetachableTabWidget.cpp
    ../ui/DetachableTabWidget.h
    ../ui/DetachablePanelManager.cpp
    ../ui/DetachablePanelManager.h
    ../ui/CaptureSessionWidget.cpp
    ../ui/CaptureSessionWidget.h
)
target_link_libraries(test_mainwindowui PRIVATE wandiag_core Qt${QT_VERSION_MAJOR}::Test Qt${QT_VERSION_MAJOR}::Widgets)
add_test(NAME test_mainwindowui COMMAND test_mainwindowui)

add_executable(test_remotetooldialog
    test_remotetooldialog.cpp
    ../ui/RemoteToolDialog.cpp
    ../ui/RemoteToolDialog.h
    ../ui/DetachablePanelManager.cpp
    ../ui/DetachablePanelManager.h
)
target_link_libraries(test_remotetooldialog PRIVATE wandiag_core Qt${QT_VERSION_MAJOR}::Test Qt${QT_VERSION_MAJOR}::Widgets)
add_test(NAME test_remotetooldialog COMMAND test_remotetooldialog)

add_test(
    NAME test_release_packaging_contract
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/release_packaging_contract.cmake
)

add_test(NAME test_batch15_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch15_contract.cmake)
add_test(NAME test_batch16_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch16_contract.cmake)
add_test(NAME test_batch18_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch18_contract.cmake)
add_test(NAME test_batch19_capture_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch19_capture_contract.cmake)

add_test(NAME test_batch20_wan_interface_card_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch20_wan_interface_card_contract.cmake)
add_test(NAME test_batch21_master_ping_policy_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch21_master_ping_policy_contract.cmake)
add_test(NAME test_batch22_ui_cleanup_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch22_ui_cleanup_contract.cmake)
add_test(NAME test_batch23_module_probe_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch23_module_probe_contract.cmake)
add_test(NAME test_batch24_router_serial_connection_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch24_router_serial_connection_contract.cmake)

add_test(NAME test_batch25_device_status_capture_fallback_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch25_device_status_capture_fallback_contract.cmake)
add_test(NAME test_batch26_workspace_upgrade_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch26_workspace_upgrade_contract.cmake)
add_test(NAME test_batch27_actual_master_endpoint_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch27_actual_master_endpoint_contract.cmake)
add_test(NAME test_batch28_compile_header_dependency_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch28_compile_header_dependency_contract.cmake)
add_test(NAME test_batch29_auto_disconnect_login_failure_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch29_auto_disconnect_login_failure_contract.cmake)

add_test(NAME test_batch30_parser_diagnostics_hardening_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch30_parser_diagnostics_hardening_contract.cmake)
add_test(NAME test_batch31_build_integration_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch31_build_integration_contract.cmake)
add_test(NAME test_batch32_realtime_parser_state_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch32_realtime_parser_state_contract.cmake)

add_test(NAME test_batch33_resizable_floating_workspace_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch33_resizable_floating_workspace_contract.cmake)

add_test(NAME test_batch34_diagnosis_detail_floating_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch34_diagnosis_detail_floating_contract.cmake)

add_test(NAME test_batch35_floating_close_reattach_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch35_floating_close_reattach_contract.cmake)

add_test(NAME test_batch36_rc13_diagnostic_reliability_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch36_rc13_diagnostic_reliability_contract.cmake)

add_test(NAME test_batch36_rc13_reliability_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch36_rc13_reliability_contract.cmake)

add_test(NAME test_batch37_field_config_snapshot_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch37_field_config_snapshot_contract.cmake)

add_test(NAME test_batch38_wan_topology_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch38_wan_topology_contract.cmake)

add_test(NAME test_batch39_windows_qt_regression_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch39_windows_qt_regression_contract.cmake)

add_test(NAME test_batch40_compact_connection_branding_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch40_compact_connection_branding_contract.cmake)

add_test(NAME test_batch41_1280_layout_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch41_1280_layout_contract.cmake)

add_test(NAME test_batch42_wan_interface_layout_regression_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch42_wan_interface_layout_regression_contract.cmake)

add_test(NAME test_batch43_capture_serial_quickcommand_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch43_capture_serial_quickcommand_contract.cmake)

add_test(NAME test_batch44_workspace_view_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch44_workspace_view_contract.cmake)
add_test(NAME test_batch45_capture_interfaces_serial_workspace_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch45_capture_interfaces_serial_workspace_contract.cmake)

add_test(NAME test_batch46_windows_compile_quickcommand_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch46_windows_compile_quickcommand_contract.cmake)
add_test(NAME test_batch47_ui_test_splitter_warning_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch47_ui_test_splitter_warning_contract.cmake)
add_test(NAME test_batch48_ui_cleanup_concurrent_diagnosis_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch48_ui_cleanup_concurrent_diagnosis_contract.cmake)

add_test(NAME test_batch49_offline_import_icon_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch49_offline_import_icon_contract.cmake)

add_test(NAME test_batch50_icon_chain_contract
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch50_icon_chain_contract.cmake)

add_test(NAME test_batch51_wan_up_serial_capture_contract
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch51_wan_up_serial_capture_contract.cmake)

add_test(NAME test_batch53_n511_serial_wan_signal_contract
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch53_n511_serial_wan_signal_contract.cmake)

add_test(NAME test_batch54_ifconfig_capture_tcp_conclusion_contract
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch54_ifconfig_capture_tcp_conclusion_contract.cmake)

add_test(NAME test_batch55_refresh_up_filter_contract
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch55_refresh_up_filter_contract.cmake)

add_test(NAME test_batch56_fast_nvram_capture_any_clean_largepcap_contract
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch56_fast_nvram_capture_any_clean_largepcap_contract.cmake)

add_test(NAME test_batch57_field_operations_ui_contract COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/batch57_field_operations_ui_contract.cmake)
