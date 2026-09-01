cmake_minimum_required(VERSION 3.16)
get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(MW "${ROOT}/MainWindow.cpp")
set(MH "${ROOT}/MainWindow.h")
set(UI "${ROOT}/MainWindow.ui")
set(DD "${ROOT}/diagnostic/DeviceDiscoveryController.cpp")
set(CS "${ROOT}/ui/CaptureSessionWidget.cpp")
set(T "${ROOT}/tests/test_mainwindowui.cpp")

function(req file needle message)
  file(READ "${file}" content)
  string(FIND "${content}" "${needle}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "${message}: missing [${needle}] in ${file}")
  endif()
endfunction()

function(forbid file needle message)
  file(READ "${file}" content)
  string(FIND "${content}" "${needle}" pos)
  if(NOT pos EQUAL -1)
    message(FATAL_ERROR "${message}: forbidden [${needle}] still present in ${file}")
  endif()
endfunction()

# Main navigation is already expressed by the four tabs; no second workspace selector.
forbid("${MW}" "comboWorkspacePreset" "workspace selector must be removed")
forbid("${MW}" "工作视图" "workspace selector label must be removed")
forbid("${MH}" "applyWorkspacePreset" "workspace preset implementation must be removed")

# Login must stay idle until the user starts diagnosis; no login-triggered discovery.
forbid("${MW}" "QTimer::singleShot(0,this,[this]{if(m_discovery&&!m_discovery->isRunning())m_discovery->start();});" "login must not auto-start discovery")
req("${MW}" "连接成功，等待手工诊断" "login state must explain that diagnosis is manual")
req("${MW}" "Background evidence collection starts only after an explicit diagnostic action" "background log must be tied to a manual diagnosis action")
req("${MW}" "Reaching this step proves a usable WAN interface was found" "one-click background evidence must start only after WAN discovery succeeds")

# WAN discovery terminates after base discovery when no usable WAN exists.
req("${DD}" "未识别到活动WAN接口" "WAN discovery must stop clearly when no active WAN is found")
req("${DD}" "ifconfig 2>/dev/null" "interface inventory must come from ifconfig")
forbid("${DD}" "__FF_IFACE__=" "device discovery must not synthesize interface names from sysfs")

# Stop after the expanded WAN/NVRAM/module-name inventory and route check; do not continue
# into tty/AT probing without WAN. Batch51 adds six NVRAM queries before this gate.
req("${DD}" "m_commands.at(m_index).contains(QStringLiteral(\"CONTROL DEVICES\"))" "WAN availability gate must run after route/NVRAM inventory before tty probing")
req("${DD}" "m_moduleProbeAttempted=false" "early WAN stop must leave module probing marked not tested")

# ifconfig parser must recognize only real ifconfig headers, not generic colon/statistics lines.
req("${DD}" "Link\\s+encap:" "legacy ifconfig interface headers must be explicit")
req("${DD}" "ipHeader" "parser compatibility may retain strict ip-link headers, while live inventory still comes only from ifconfig")
req("${T}" "captureInterfaceSelectorUsesActualListAndManualInput" "UI regression must verify ifconfig-only dropdown plus manual text")

# Capture dropdown contains only actual ifconfig inventory; arbitrary names remain editable text only.
forbid("${MW}" "QStringList names{QStringLiteral(\"any\")}" "main capture dropdown must not inject any")
forbid("${CS}" "QStringList names{QStringLiteral(\"any\")}" "independent capture dropdown must not inject any")
req("${MW}" "下拉仅显示 ifconfig 实际接口" "main capture selector must explain source")
req("${CS}" "下拉仅显示 ifconfig 实际接口" "independent capture selector must explain source")

# Stop diagnosis is globally reachable while the user switches tabs/tools.
req("${MW}" "btnGlobalStopDiagnosis" "global stop diagnosis action must exist")
req("${MW}" "addPermanentWidget" "global stop diagnosis must live outside a single tab")

# Cards use plain field-friendly states instead of raw AT strings.
req("${MW}" "cardStateText" "status cards need normalized plain-language states")
req("${MW}" "QStringLiteral(\"ERROR\")" "error card state must be explicit")
req("${UI}" "WAN IP\\n未测试" "WAN IP card must start with a plain untested state")
req("${UI}" "无线信号\\n未测试" "signal card must start with a plain untested state")


# Device cards stay compact and field-friendly: module face prefers model, firmware remains detail/tooltip only.
req("${MW}" "QString moduleCardText(const QString& model,LayerState fallbackState)" "module card helper must prefer model only")
forbid("${MW}" "moduleCardText(const QString& model,const QString& firmware" "module card must not combine model and firmware")
req("${MW}" "const QString moduleCardValue" "module card must choose model or normalized fallback state")
req("${MW}" "const QString simCardValue" "SIM card must use normalized plain state")
req("${MW}" "const QString registrationCardValue" "registration card must use normalized plain state")

# Capture controls are simplified and irrelevant target inputs are hidden by mode.
req("${MW}" "setCaptureTargetVisible" "capture target visibility must follow mode")
req("${T}" "workspaceSelectorIsRemoved" "UI regression must verify workspace selector removal")
req("${T}" "serialConnectionLayoutSurvivesResponsiveReflow" "UI regression must protect serial connection layout")
req("${T}" "captureModeHidesIrrelevantTargetFields" "UI regression must protect simplified capture layout")

message(STATUS "Batch48 UI cleanup/concurrent diagnosis contract passed")
