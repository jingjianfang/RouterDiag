Batch53 - N511 / serial capture / active WAN / signal display

1. N511 at_test compatibility
   - Filters --> / <-- and at_test banner/help noise.
   - ATI seeds manufacturer/model/firmware when available (e.g. NEOWAY / N511 / V006).
   - at_test OK detection tolerates leading/trailing whitespace.
   - Adds NVRAM controldevice/3gdata/backup device hints before ttyUSB/ttyACM inventory.
   - Real-time AT identity remains higher priority than NVRAM module names.

2. Serial shared-console capture
   - tcpdump -xx runs in background and returns its exact PID, leaving the shell usable.
   - Stop sends SIGINT to that PID and verifies shell recovery with __FF_SERIAL_READY__.
   - Ctrl-C remains a recovery nudge only when the shared shell is unexpectedly busy.

3. Active WAN tightening
   - NVRAM interface names are accepted as active WAN only when ifconfig confirms UP + usable IPv4.
   - NVRAM-IP matching and default-route fallback also require a live UP interface.
   - A down configured WAN is no longer reported as the current active WAN.

4. Wireless signal card
   - Displays only RSRP and SINR.
   - RSRQ/CSQ remain available internally for diagnosis but are not shown on the signal card.
