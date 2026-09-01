FourFaith RouterDiag v1.3 RC13 - Batch39 Windows/Qt Regression Alignment

Purpose
-------
Batch39 is driven by the first complete Windows + VS2022 + Qt 6.8.3 build/CTest run of Batch38.
It fixes two real runtime diagnosis defects and aligns stale unit tests with the already-approved RC13 presentation/capture/shortcut behavior.

Runtime fixes
-------------
1. Preserve specific SIM CME diagnosis. `+CME ERROR: 10` remains `SIM未插入`; the generic CPIN error fallback no longer overwrites a specific CME mapping with `ERROR`.
2. FIN diagnosis always identifies the exact endpoint that initiated FIN when that endpoint is known, including the warning case where bidirectional business payload was not observed.

Test alignment
--------------
- Field report/UI: six internal diagnostic layers remain intact, while UI/report presentation is four grouped layers: access (module/SIM/registration), WAN/IP, transport, business data.
- Master capture filter: business TCP is intentionally captured by port without restricting it to the configured master IP so NAT/cluster/backup-source actual endpoints can be discovered; ICMP remains tied to the configured/reference master IP.
- Quick commands: tests now validate the Batch36 category/search/four-column table model and category-aware persisted/builtin entries.
- Qt AUTOMOC test classes place `Q_OBJECT` on its own line to avoid misleading AutoMoc warnings on VS2022/Qt 6.8.3.

Expected Windows verification
-----------------------------
Rebuild first, then run CTest:
  cmake --build out\build\release-test --config Release --parallel
  ctest --test-dir out\build\release-test -C Release --output-on-failure

Batch39 adds one static contract test, so a full run contains 53 tests.
