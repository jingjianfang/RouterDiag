RC13 Batch50 - Windows icon chain fix
=====================================

Scope
-----
This batch only fixes application icon propagation. WAN detection, diagnosis,
capture, offline analysis and field behavior are unchanged from Batch49.

Changes
-------
1. Qt runtime icon now loads the embedded PNG resource
   :/icons/app_icon_1024.png instead of decoding the ICO at runtime.
   This avoids depending on the imageformats/icon plugin directories that the
   lite field package intentionally removes.

2. MainWindow explicitly inherits QApplication::windowIcon(), so the title-bar
   and Windows taskbar icon follow the same product artwork.

3. The native WanDiagTool.exe still embeds resources/fourfaith_routerdiag.ico
   through resources/app_icon.rc. The ICO contains 16/24/32/48/64/128/256 px
   images.

4. package_onefile_release_lite.bat now applies the same ICO to the final
   IExpress one-file wrapper after packaging and before SHA256 generation.
   packaging/set_exe_icon.ps1 uses the Windows resource-update APIs and verifies
   that RT_GROUP_ICON resource id 1 exists after the write.

Validation
----------
- Batch15..Batch50 static/release contracts pass in the source verification
  environment.
- MainWindow.ui and app_icon.qrc parse as XML.
- PNG and ICO structures are validated; ICO contains seven expected sizes.
- Windows Qt/MSVC runtime and the final IExpress wrapper must still be verified
  on the target Windows 11 + Qt 6.8.3 / MSVC 2022 environment.

Expected Windows CTest total: 64 tests.
