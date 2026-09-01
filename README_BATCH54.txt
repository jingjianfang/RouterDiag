Batch54 - ifconfig 网口详情 / 串口抓包前检查 / TCP结论增强

1. 网口详情
- 设备自动检测的接口库存改为普通 `ifconfig`，不再使用 `ifconfig -a`。
- 网口详情表只显示 ifconfig 中处于 UP 状态的接口。
- 网口详情只显示接口名、IPv4、UP 状态；不再在表格里叠加“WAN接口”等 NVRAM/WAN 推断。
- 网口详情内原 WAN/自动检测摘要隐藏，WAN/模组信息继续由上方独立状态卡片展示。

2. 实时抓包启动修复
- 串口控制台会回显并折行长命令，旧的 __WANDIAG_NO_IFACE__/__WANDIAG_CAPTURE_OK__ 文本可能因命令回显造成误判。
- 抓包前检查改为使用 TelnetClient 已解析的真实 shell exit code：0=通过，2=接口不可用，127=tcpdump 不存在。
- 因此 br0 明明存在于 ifconfig 时，不会再因为命令回显中的错误标记文本而被误判为不存在。

3. TCP连接结果进入综合结论
- 已形成实际 TCP 判断时，主站/终端网口 TCP 结果除了保留在 TCP 会话/证据中，也追加到“综合结论”。
- 未测试、等待测试、被 WAN 前置条件阻断的 TCP 项不会伪造成测试结果。
