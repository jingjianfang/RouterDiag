Batch52 - WAN source label compatibility fix

Root cause:
- WAN interface/IP selection was correct.
- DeviceDiscoveryResult::wanIpSource emitted "接口 <if> IPv4（wan_ifname）".
- Existing Qt regression test also requires the source label to identify the hint explicitly as "NVRAM接口".

Fix:
- NVRAM interface hint labels now emit both the human-readable category and the exact NVRAM key:
  * NVRAM接口 wan_ifname
  * NVRAM接口 bkup_wan_ifname
  * NVRAM接口 wan_ifname2
- This preserves the Batch51 WAN selection priority and remains compatible with tests checking the exact key name.
- Added regression assertion requiring both "NVRAM接口" and "wan_ifname".

No WAN-selection priority, interface-UP filtering, or serial tcpdump behavior was changed in Batch52.
