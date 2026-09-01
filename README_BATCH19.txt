FourFaith RouterDiag v1.2 Batch 19 - realtime capture startup compatibility hotfix

Fixes:
1. Removes the `tcpdump -d` preflight dependency. Some embedded router tcpdump builds can capture normally but do not support desktop tcpdump's -d option; older logic incorrectly reported this as an invalid BPF.
2. Prepares the capture Telnet PTY with `stty raw -echo` before switching to PCAP binary mode, preventing the shell from echoing the tcpdump command into the PCAP stream.
3. Redirects tcpdump stderr to /tmp/wandiag_tcpdump.err instead of /dev/null.
4. If no PCAP global header arrives, reads the router-side tcpdump stderr and surfaces the real startup error.
5. Updates packet-capture unit/contract tests and the older Batch15 contract to the new compatibility behavior.

Windows validation after overlay:
  cmake --build out\build\debug --config Debug --target test_packetcapturecontroller test_mainwindowui WanDiagTool
  ctest --test-dir out\build\debug -C Debug -R "test_packetcapturecontroller|test_mainwindowui|test_batch15_contract|test_batch19_capture_contract" --output-on-failure
  verify_v1.2_debug.bat
