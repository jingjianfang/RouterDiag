FourFaith RouterDiag v1.2 - Batch 20

Change: WAN status card simplification

- The top WAN card now represents interface detection only.
- After detection it shows only the actual interface name, e.g. eth0 / eth1 / usb0 / ppp0.
- If no interface has been detected it shows "未检测".
- WAN IP remains a separate card and keeps its own IP/source logic.
- WAN health/diagnosis logic is unchanged; this batch only separates interface display from WAN/IP health state.

Windows validation after overlay:
  cmake --build out\build\debug --config Debug --target test_mainwindowui WanDiagTool
  ctest --test-dir out\build\debug -C Debug -R "test_mainwindowui|test_batch20_wan_interface_card_contract" --output-on-failure
  verify_v1.2_debug.bat
