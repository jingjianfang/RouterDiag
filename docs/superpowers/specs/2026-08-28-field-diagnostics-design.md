# WanDiagTool v1.2 现场综合诊断设计

## 1. 目标

在现有 Qt/C++ WAN 诊断与 PCAP 实时流解析基础上，加入现场常用的主站通道、终端侧网口/串口、模块日志和快捷命令诊断能力。保持“路由器不落盘 PCAP，tcpdump 二进制流直接送到 PC 端解析”的现有架构。

## 2. 默认连接参数

- 默认路由器 IP：保持当前默认值 `192.168.1.1`。
- Telnet 端口：`23`。
- 默认用户名：`admin`。
- 默认密码：`admin`。
- 主站业务端口默认值：`2404`。

## 3. 主站通道诊断

### 3.1 输入

- 主站 IP：可空。
- 业务端口：默认 `2404`。

### 3.2 在线流程

1. 从现有 WAN 诊断结果获取实际 WAN 接口，如 `ppp0`、`usb0`。
2. 主站 IP 非空时，在路由器执行 `ping` 测试主站可达性。
3. 抓包时使用现有二进制 PCAP 流：
   - 有主站 IP 和端口：`host <主站IP> and port <端口>`。
   - 只有主站 IP：`host <主站IP>`。
   - 只有端口：`port <端口>`。
4. PacketAnalyzer 对目标主站会话建立证据：SYN、SYN-ACK、ACK、PSH+ACK、RST、FIN、重传、ICMP。
5. 识别 140 字节 ICMP 报文作为可配置/辅助证据，不把它单独当成所有现场的通用成功条件。

### 3.3 结论

至少区分：
- 主站 Ping 成功/失败/未测试。
- TCP 三次握手完成。
- 只有 SYN、未收到 SYN-ACK。
- 收到 RST。
- 已有 PSH+ACK 业务数据。
- 有明显重传。
- 未观察到目标主站流量。

## 4. 路由器与终端通讯方式

界面增加：
- `网口`
- `串口`

### 4.1 网口模式

输入：终端 IP。

诊断流程：
1. 检查终端 IP 格式。
2. 通过控制 Telnet 在路由器执行 `ping`。
3. Ping 成功：结论为“路由器到终端网口可达”，并允许一键启动终端侧抓包。
4. 终端侧抓包固定接口 `br0`，过滤器为 `host <终端IP>`：
   `tcpdump -i br0 -U -s 0 -w - 'host <终端IP>'`
5. PC 端继续复用 PcapStreamReader、PacketParser、PacketAnalyzer。
6. Ping 失败：结论为“路由器到终端网口不通”，建议检查终端 IP、网段、网线、LAN 口、终端网卡。

### 4.2 串口模式

第一版只加入通用串口/AT 测试，不猜测私有终端协议。

输入：
- 串口设备节点，默认 `/dev/ttyUSB0`。

功能：
- 快捷执行 `at_test <设备节点>`。
- 显示原始命令结果。
- 将“设备存在/命令可执行/返回可识别”作为串口侧诊断证据。

暂不加入波特率修改、串口透传和私有协议解析，除非后续拿到设备命令或协议说明。

## 5. 模块与系统日志

新增日志工具区：
- 查看 `nvram get debuglog_enable`。
- 查看 `nvram get syslogd_enable`。
- 查看 `/tmp/.systemlog` 尾部内容。
- 用户主动点击“启用详细日志”后才执行：
  - `nvram set debuglog_enable=1`
  - `nvram set syslogd_enable=3`

不在“一键诊断”中静默修改 NVRAM。

持续 `tail -f` 由于当前 TelnetClient 的单命令状态机与 PCAP 抓包并发会互相影响，v1.2 第一阶段采用“刷新日志尾部”而不是永久 tail；后续如需持续日志流，再使用独立第三路 Telnet 连接。

## 6. 高级快捷终端

新增命令终端区域，复用控制 Telnet：
- 用户可输入任意命令并查看结果。
- 保存本次运行期间的命令历史。
- 快捷命令：
  - `ifconfig`
  - `ps`
  - `netstat`
  - `logread`
  - `dmesg`
  - `free`
  - `uptime`
  - `at_test /dev/ttyUSB0`

在线诊断进行中时，禁止并发执行另一个控制命令，避免当前 TelnetClient 状态机串话。

## 7. 诊断报告结构

最终报告拆成四块：

1. 路由器 ↔ 运营商/WAN
   - 模组、SIM、注册、PPP/LCP/IPCP、WAN IP。
2. 路由器 ↔ 主站
   - Ping、目标端口、三次握手、PSH+ACK、RST/FIN、重传、ICMP 证据。
3. 路由器 ↔ 终端
   - 通讯方式。
   - 网口：终端 IP、Ping、br0 抓包证据。
   - 串口：设备节点、AT 测试结果。
4. 模块/系统日志
   - debuglog/syslog 配置、systemlog 摘要与异常证据。

## 8. 代码边界

新增/调整单元：

- `diagnostic/ConnectivityProbe.*`
  - 生成安全的 ping 命令并解析 ping 输出。
- `diagnostic/ChannelDiagnosis.*`
  - 从 ParsedPacket/CaptureStats 聚合主站或终端链路结论。
- `diagnostic/FieldDiagnosticController.*`
  - 串行调度主站 Ping、终端 Ping、串口测试、日志配置查询等控制命令。
- `capture/PacketAnalyzer.*`
  - 补充 SYN-ACK、ACK、PSH+ACK、目标会话相关统计。
- `capture/PcapTypes.h`
  - 增加用于通道诊断的统计字段；ParsedPacket 增加 TCP payload length/IP total length 等必要信息。
- `MainWindow.* / MainWindow.ui`
  - 新输入项、按钮、终端模式切换、现场诊断结果展示与快捷终端。
- `report/ReportExporter.*`
  - 把现场综合诊断结果纳入报告。

不修改 Telnet IAC/PCAP 二进制流的基本架构。

## 9. 安全与输入处理

- 接口名继续限制为安全字符集合。
- IPv4 输入使用 Qt 地址解析校验，不把任意字符串拼到 shell。
- 业务端口限定 1..65535。
- 串口设备节点只允许 `/dev/` 下由字母、数字、`_-.` 组成的名称。
- 用户自定义高级终端命令属于显式高级操作，不用于自动诊断流程。

## 10. 测试

新增单元测试覆盖：
- Ping 成功、100% 丢包、BusyBox 常见格式。
- 主站 SYN → SYN-ACK → ACK 判定。
- 只有 SYN 无响应。
- PSH+ACK 业务数据检测。
- RST/FIN/重传统计。
- 140 字节 ICMP 辅助证据。
- `br0 host <终端IP>` tcpdump 命令构造。
- 默认账号密码、默认端口和 UI 模式切换的最小验证。
- 串口设备节点校验与 `at_test` 命令构造。

现有离线 PCAP 和日志测试必须继续通过。
