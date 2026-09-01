FourFaith RouterDiag v1.2 - Batch 16

Changes:
1. Main window minimum size reduced to 900x600.
2. Whole main content is protected by a QScrollArea so small windows scroll instead of overlapping controls.
3. Connection, device status cards and realtime-capture controls reflow at widths below 1180px.
4. Product title reduced to 20px.
5. Module-log viewer uses exactly: tail /tmp/.systemlog -f
6. Module-log Telnet stream is rendered as a stream, not as artificial per-readyRead lines.
   This fixes chunk splits such as "t" on one line and "ail ..." on the next.
7. Module-log UI refreshes every 50ms, follows the latest line while the user stays at the bottom,
   and stops forcing scroll when the user reviews older text.
8. Raw module-log stream is saved without synthesized line breaks; GUI keeps the latest 5000 blocks.
9. Module-log status shows command, last-data time and received line count; 10s idle means connected/no new log.
10. Live LogAnalyzer extraction remains active for module/SIM/registration/WAN/RSRP/RSRQ/SINR.

Windows verification after copying this patch:
  cmake --build out\build\debug --config Debug --target test_mainwindowui test_remotetooldialog WanDiagTool
  ctest --test-dir out\build\debug -C Debug -R "test_mainwindowui|test_remotetooldialog|test_batch16_contract" --output-on-failure
  verify_v1.2_debug.bat
