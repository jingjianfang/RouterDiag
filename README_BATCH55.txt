Batch55 - refresh interface UP-only consistency patch

1. Manual "refresh interfaces" now explicitly filters DeviceDiscoveryParser results to info.up == true.
2. Interface details and capture-interface dropdown therefore share the same UP-only inventory after manual refresh.
3. The table is rebuilt from the filtered list and only displays status "UP".
4. Added batch55_refresh_up_filter_contract.cmake to prevent automatic/manual paths from diverging again.
