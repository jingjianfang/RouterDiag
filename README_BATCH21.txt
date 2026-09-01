FourFaith RouterDiag v1.2 - Batch 21

Change: master-station ICMP-disabled compatibility

- Ping is auxiliary evidence for the master station, not a standalone reachability verdict.
- A normal Ping timeout / 100% loss with no TCP packets is now reported as inconclusive (Unknown), because the master station may block ICMP Echo.
- One-click diagnosis continues into master TCP capture after Ping completes, regardless of whether Echo Reply is received.
- TCP evidence remains authoritative: successful handshake/session/payload can make the master channel normal even when Ping has no reply.
- Explicit IP-layer failures remain distinguishable from ICMP blocking:
  - Network is unreachable -> explicit route failure / Error.
  - Destination Host Unreachable -> explicit IP-layer failure / Error.
- The Ping result UI no longer labels every no-reply case as "unreachable"; ordinary timeout is shown as "未收到ICMP应答".
- Added PingFailureKind classification and regression/contract tests for the policy.

Validation on Windows (VS2022 + Qt):
  cmake --build out\build\debug --config Debug --target test_connectivityprobe test_channelanalyzer test_mainwindowui WanDiagTool
  ctest --test-dir out\build\debug -C Debug -R "test_connectivityprobe|test_channelanalyzer|test_mainwindowui|test_batch21_master_ping_policy_contract" --output-on-failure
  verify_v1.2_debug.bat

Note:
The Linux editing environment used for this batch did not contain Qt development packages, so the Qt targets could not be compiled locally. The standalone Batch 21 CMake contract test was executed successfully.
