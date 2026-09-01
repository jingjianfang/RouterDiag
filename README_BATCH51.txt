RC13 Batch51 - WAN/NVRAM优先、UP接口刷新、串口共享控制台抓包修复

1. 抓包“刷新接口”改为普通 ifconfig，不再使用 ifconfig -a；主窗口和独立抓包窗口的下拉列表只加入状态为 UP 的接口。
2. 下拉列表之外仍允许手工输入 tcpdump 接口名，手工抓包接口不会反向改变 WAN 诊断结果。
3. WAN 自动识别优先采用 ifconfig 实际接口 + NVRAM 明确提示：wan_ifname、bkup_wan_ifname、wan_ifname2；WAN IP 优先取被确认接口上的 ifconfig IPv4，再使用 wan_ipaddr / bkup_wan_ipaddr / comm_wan_ipaddr 兜底。
4. 默认路由降为辅助/兜底证据，不再覆盖已经由 ifconfig + NVRAM 确认的 WAN。
5. 模组自动识别增加 NVRAM 来源：comm_name、submodulename、current_module_name。AT 实时识别成功时仍以 AT 型号为准；AT 未运行或未响应时可显示 NVRAM 模组标识。
6. 串口控制台连接路由器时，tcpdump -xx 改用不追加命令完成标记的长命令模式；Ctrl-C 后以路由器提示符作为完成条件，并在串口发送 Ctrl-C 后主动 flush，避免 BusyBox ash 中断 tcpdump 后未执行尾部 marker 导致抓包会话卡死/无法恢复。
7. 新增 Batch51 静态回归契约，并扩展 DeviceDiscovery 单元测试覆盖“备 WAN 接口 NVRAM + live ifconfig IP”以及“NVRAM WAN 优先于默认路由”的场景。

验证说明：
- 已逐个运行 tests/*.cmake，共 38 个静态契约，全部通过。
- 当前 Linux 容器未安装 Qt5/Qt6 开发包；CMake 配置在 find_package(QT) 阶段停止，因此本环境无法完成 Qt 编译/QtTest。
