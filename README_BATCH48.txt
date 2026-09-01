RC13 Batch48 - UI cleanup / manual diagnosis / ifconfig-only capture interfaces
==========================================================================

This batch closes the UI and field-behavior issues found during Batch47 field use:

1. Remove the redundant "工作视图" selector. The four main tabs are the only workspace navigation.
2. Simplify realtime capture controls. The new capture-window action lives in the packet panel header;
   target IP/port are shown only for modes that need them; the filter remains directly editable.
3. Capture interface dropdowns list only interface names actually returned by router `ifconfig`.
   No `any`, sysfs candidate or guessed interface is injected into the dropdown. The combo remains
   editable, so operators can still manually type `tun0`, `any`, or another tcpdump interface.
4. Harden BusyBox ifconfig parsing so statistic lines such as `collisions:` / `Interrupt:` cannot be
   mistaken for interface names.
5. Connecting/logging in no longer starts device discovery or background module-log analysis automatically.
   Detection/evidence collection starts only after an explicit diagnosis action.
6. If the bounded WAN inventory finds no credible WAN interface, discovery stops immediately and does
   not continue into modem tty/AT probing. The UI reports the WAN as unidentified and the skipped modem
   checks as not tested.
7. Add a global "停止诊断" action in the status bar while one-click diagnosis is running, so the user
   can switch to capture/offline/tools pages and still stop the workflow.
8. Connection layout reflow is reapplied after mode/state changes to keep serial/network controls from
   overlapping at 1280-class widths.
9. Device cards use short field-friendly states such as `正常 / ERROR / 未识别 / 未测试`. Raw AT text
   such as `READY` and modem model/firmware strings stay in tooltip/detail evidence instead of being
   concatenated onto the card face. WAN interface/IP and radio measurements remain visible where useful.
10. Existing Batch15-Batch47 contracts are updated only where Batch48 intentionally supersedes the old
    workspace selector / interface injection behavior.

Windows verification target: 62 CTest tests.
