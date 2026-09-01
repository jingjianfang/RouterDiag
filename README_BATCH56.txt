Batch56 - Fast NVRAM / Capture any / Clean Output / Large PCAP

- Routine WAN/module/SIM/network/signal state is read in one batched `nvram get` round-trip. `this_is_bkup=1` selects backup-card (`bkup_*`) values first; missing backup signal/network values fall back to live `comm_*` values.
- Live NVRAM `comm_module_status`, `comm_dial_status`, `comm_network`, SIM state and `comm_softver` are used immediately; AT remains the real-time identity/status fallback when NVRAM is missing or suspicious.
- Interface inventory/details remain ordinary `ifconfig` and UP-only. NVRAM never injects interfaces into the interface detail table.
- Capture mode maps WAN/master to the detected WAN, terminal-Ethernet to the terminal/LAN interface, and custom capture leaves the interface user-selectable. `any` is a tcpdump pseudo-interface that captures all interfaces.
- Synchronized workflow capture suppresses redundant interface refresh. Router serial-control mode uses one `tcpdump -i any` session so two captures cannot fight for the same shell.
- All user-visible Telnet/serial command streams use one sanitizer that removes command echo, wrapper fragments, `__FF_CMD_DONE_*`, `__ff_rc`, AT helper markers and shell/login prompts. Raw text remains available internally for tcpdump parsing.
- `.pcap / .cap / .pcapng / .pap` import is analyzed immediately. File I/O is chunked; the visible table retains the latest 20,000 packets. Files over 64 MiB skip the replay cache to avoid retaining a second full packet copy in memory.
- Replay remains optional for smaller imports; large imports stay fully analyzed/displayed even when timed replay is disabled.
- Terminal Ethernet diagnosis validates the configured terminal IP against `br0` / `br0:1` IPv4+netmask parsed from ordinary `ifconfig`; if neither LAN subnet matches, diagnosis stops with an explicit configuration-error prompt.
