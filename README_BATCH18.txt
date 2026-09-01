FourFaith RouterDiag v1.2 - Batch 18 UI/Logic Closure
=====================================================

Scope
-----
1. WAN discovery now queries wan_ifname, wan_ipaddr, bkup_wan_ipaddr and live interface IPv4.
   Priority: live IPv4 on detected WAN interface -> wan_ipaddr -> bkup_wan_ipaddr.
   UI reports the selected WAN IP source.
2. Field Ping streams the router's raw ping output in real time and keeps parsed sent/received/loss/RTT/failure reason.
3. Remote Ping tool also keeps the raw live output and shows a parsed completion summary.
4. Capture UI explicitly distinguishes starting, running with 0 matching packets, running with packets, and failure.
5. TCP packet-list Length is TCP payload length (tcpdump "length N"); frame/IP lengths remain in packet details.
6. Realtime/offline TCP business analysis now uses sequence-aware TCP stream reassembly, ignores full retransmissions and never invents missing bytes.
7. Terminal Ping-only failure is conservative: ICMP failure without TCP evidence is Warning, not proof of terminal failure.
8. Upstream registration/WAN failure blocks downstream master-link failure conclusions unless stronger TCP/Ping-success evidence exists.
9. Shared control Telnet exposes busy state; WAN diagnosis, discovery, Ping and capture preflight refuse to overwrite another active command.
10. RSRP/RSRQ/SINR/RSSI/CSQ remain visible; qualitative hints combine plausible RSRP/SINR values instead of blaming weak signal from CSQ alone.
11. Master capture mode uses the auto-detected WAN interface; terminal Ethernet capture remains fixed to br0.
12. Main window minimum size is 800x520 with narrow responsive reflow; title remains compact at 18 px and tabs use a lighter underline style.
13. Module log viewer remains exact live command: tail /tmp/.systemlog -f, 50 ms UI refresh, raw local saving and live SIM/module/registration/WAN/signal extraction.

Windows verification
--------------------
Build selected targets:
cmake --build out\build\debug --config Debug --target test_connectivityprobe test_devicediscovery test_diagnosisengine test_channelanalyzer test_tcpstreamreassembler test_mainwindowui test_remotetooldialog WanDiagTool

Run selected tests:
ctest --test-dir out\build\debug -C Debug -R "test_connectivityprobe|test_devicediscovery|test_diagnosisengine|test_channelanalyzer|test_tcpstreamreassembler|test_mainwindowui|test_remotetooldialog|test_batch18_contract" --output-on-failure

Then full regression:
verify_v1.2_debug.bat

Expected full suite after this batch: 26 tests.

Field release after full verification:
package_onefile_release_lite.bat
