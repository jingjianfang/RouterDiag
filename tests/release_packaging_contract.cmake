cmake_minimum_required(VERSION 3.20)

set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(PACKAGE_SCRIPT "${ROOT}/package_onefile_release.bat")
set(DEPLOY_DOC "${ROOT}/docs/DEPLOYMENT.md")

if(NOT EXISTS "${PACKAGE_SCRIPT}")
    message(FATAL_ERROR "package_onefile_release.bat is missing")
endif()
if(NOT EXISTS "${DEPLOY_DOC}")
    message(FATAL_ERROR "docs/DEPLOYMENT.md is missing")
endif()

file(READ "${PACKAGE_SCRIPT}" PACKAGE_TEXT)
file(READ "${ROOT}/CMakeLists.txt" CMAKE_TEXT)
file(READ "${DEPLOY_DOC}" DEPLOY_TEXT)

foreach(REQUIRED_TEXT
    "--config Release"
    "windeployqt.exe"
    "--compiler-runtime"
    "platforms\\qwindows.dll"
    "VCToolsRedistDir"
    "payload.zip"
    "iexpress.exe"
    "FourFaith_RouterDiag_v1.2.exe"
    "certutil -hashfile"
)
    string(FIND "${PACKAGE_TEXT}" "${REQUIRED_TEXT}" FOUND_AT)
    if(FOUND_AT EQUAL -1)
        message(FATAL_ERROR "Packaging contract missing: ${REQUIRED_TEXT}")
    endif()
endforeach()


set(SED_TEMPLATE "${ROOT}/packaging/onefile.sed.in")
if(NOT EXISTS "${SED_TEMPLATE}")
    message(FATAL_ERROR "packaging/onefile.sed.in is missing")
endif()
file(READ "${SED_TEMPLATE}" SED_TEXT)

foreach(REQUIRED_SED_TEXT
    "TargetName=%TargetName%"
    "FriendlyName=%FriendlyName%"
    "AppLaunched=%AppLaunched%"
    "PostInstallCmd=%PostInstallCmd%"
    "TargetName=@TARGET@"
    "FriendlyName=FourFaith RouterDiag v1.2"
    "AppLaunched=wscript.exe launch.vbs"
)
    string(FIND "${SED_TEXT}" "${REQUIRED_SED_TEXT}" FOUND_AT)
    if(FOUND_AT EQUAL -1)
        message(FATAL_ERROR "IExpress SED contract missing: ${REQUIRED_SED_TEXT}")
    endif()
endforeach()

string(FIND "${PACKAGE_TEXT}" "iexpress.exe\" /N onefile.sed" HAS_RELATIVE_SED_CALL)
if(HAS_RELATIVE_SED_CALL EQUAL -1)
    message(FATAL_ERROR "IExpress must be invoked from the packaging work directory with relative onefile.sed")
endif()

string(FIND "${CMAKE_TEXT}" "WIN32_EXECUTABLE TRUE" HAS_WIN32_GUI)
if(HAS_WIN32_GUI EQUAL -1)
    message(FATAL_ERROR "WanDiagTool must be built as a Windows GUI executable")
endif()

set(LITE_PACKAGE_SCRIPT "${ROOT}/package_onefile_release_lite.bat")
if(NOT EXISTS "${LITE_PACKAGE_SCRIPT}")
    message(FATAL_ERROR "package_onefile_release_lite.bat is missing")
endif()
file(READ "${LITE_PACKAGE_SCRIPT}" LITE_PACKAGE_TEXT)

foreach(REQUIRED_LITE_TEXT
    "windeployqt.exe"
    "FourFaith_RouterDiag_v1.2.exe"
    "Qt6Core.dll"
    "Qt6Gui.dll"
    "Qt6Network.dll"
    "Qt6Widgets.dll"
    "platforms\\qwindows.dll"
    "VCToolsRedistDir"
    "vc_redist.x64.exe"
    "opengl32sw.dll"
    "d3dcompiler_47.dll"
    "dxcompiler.dll"
    "dxil.dll"
    "Qt6Svg.dll"
    "payload.zip"
    "iexpress.exe"
    "certutil -hashfile"
)
    string(FIND "${LITE_PACKAGE_TEXT}" "${REQUIRED_LITE_TEXT}" FOUND_AT)
    if(FOUND_AT EQUAL -1)
        message(FATAL_ERROR "Lite packaging contract missing: ${REQUIRED_LITE_TEXT}")
    endif()
endforeach()

foreach(PRUNED_PLUGIN_DIR
    "generic"
    "iconengines"
    "imageformats"
    "networkinformation"
    "tls"
)
    string(FIND "${LITE_PACKAGE_TEXT}" "${PRUNED_PLUGIN_DIR}" FOUND_AT)
    if(FOUND_AT EQUAL -1)
        message(FATAL_ERROR "Lite packaging must explicitly prune plugin directory: ${PRUNED_PLUGIN_DIR}")
    endif()
endforeach()

string(FIND "${LITE_PACKAGE_TEXT}" [=[if exist "%STAGE_DIR%\styles\qmodernwindowsstyle.dll"]=] HAS_STYLE_PRESERVATION)
if(HAS_STYLE_PRESERVATION EQUAL -1)
    message(FATAL_ERROR "Lite packaging must preserve qmodernwindowsstyle.dll when windeployqt deploys it")
endif()

string(FIND "${LITE_PACKAGE_TEXT}" [=[iexpress.exe" /N onefile.sed]=] HAS_LITE_RELATIVE_SED_CALL)
if(HAS_LITE_RELATIVE_SED_CALL EQUAL -1)
    message(FATAL_ERROR "Lite IExpress must be invoked from the packaging work directory with relative onefile.sed")
endif()

foreach(REQUIRED_DOC_TEXT
    "无需安装 Qt"
    "无需安装 Visual Studio"
    "SmartScreen"
    "临时目录"
)
    string(FIND "${DEPLOY_TEXT}" "${REQUIRED_DOC_TEXT}" FOUND_AT)
    if(FOUND_AT EQUAL -1)
        message(FATAL_ERROR "Deployment document missing: ${REQUIRED_DOC_TEXT}")
    endif()
endforeach()

message(STATUS "Release packaging contract satisfied")

set(LAUNCHER "${ROOT}/packaging/launch_onefile.vbs")
if(NOT EXISTS "${LAUNCHER}")
    message(FATAL_ERROR "packaging/launch_onefile.vbs is missing")
endif()
file(READ "${LAUNCHER}" LAUNCHER_HEX HEX)
string(REGEX MATCH "^([0-7][0-9A-Fa-f])*$" LAUNCHER_IS_ASCII "${LAUNCHER_HEX}")
if(LAUNCHER_IS_ASCII STREQUAL "")
    message(FATAL_ERROR "launch_onefile.vbs must stay ASCII-only for Windows Script Host compatibility")
endif()
