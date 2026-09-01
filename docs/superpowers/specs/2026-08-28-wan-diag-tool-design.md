# WAN 自动诊断与实时抓包工具设计规格

## 1. 目标

开发一个基于 VS2022 + Qt C++ Widgets 的桌面工具，通过 Telnet 连接嵌入式路由器，实现：

1. 自动诊断 WAN 无 IP / 拨号失败问题。
2. 自动解析蜂窝模组、SIM、注册、附着、PPP/IPCP、WAN IP、链路错误。
3. 通过路由器执行 `tcpdump -U -s 0 -w -`，直接把 PCAP 二进制流传回 PC。
4. 路由器端不生成 `.pcap` 文件。
5. PC 端可实时解析、统计和显示抓包结果。
6. 用户可选择将当前 PCAP 数据导出为本地 `.pcap` 文件并用 Wireshark 打开。

## 2. 技术栈

- Visual Studio 2022
- Qt 5.15.x / Qt 6.x
- Qt Widgets
- Qt Network (`QTcpSocket`)
- CMake
- C++17
- 不依赖 Python
- 核心功能不依赖 Npcap / WinPcap / libpcap

## 3. 总体架构

应用使用两个独立 Telnet 连接。

### 3.1 Control Telnet

负责登录、`nvram`/`ifconfig`/日志读取、PID 查询、停止 tcpdump 等文本命令。

### 3.2 Capture Telnet

执行：

```sh
exec tcpdump -i <wan_ifname> -U -s 0 -w - '<filter>'
```

命令启动后，该 socket 专门接收 PCAP 二进制数据：

```text
Router tcpdump
    ↓
Telnet socket
    ↓
Telnet IAC decoder
    ↓
Raw PCAP stream
    ↓
PcapStreamReader
    ├── PacketParser
    ├── PacketAnalyzer
    └── Local PCAP buffer/writer
```

## 4. 模块划分

### 4.1 TelnetClient

职责：TCP 建连、用户名/密码登录、Telnet IAC 协商、文本命令执行、超时、断线处理和二进制抓包模式。

```cpp
enum class TelnetMode {
    CommandMode,
    PcapStreamMode
};
```

`CommandMode` 输出清洗后的 shell 文本；`PcapStreamMode` 输出剥离 Telnet 控制序列并完成 IAC 转义还原的原始字节。

### 4.2 DiagnosticController

优先执行：

```text
nvram get wan_ifname
nvram get wan_ipaddr
nvram get bkup_wan_ipaddr
ifconfig
nvram get debuglog_enable
nvram set debuglog_enable=3
nvram commit
tail -n 500 /tmp/.systemlog
```

若命令不可用则降级到 `ip addr`、`logread`、`/var/log/messages`。诊断结束时仅在原值成功读取时恢复 `debuglog_enable`。

### 4.3 LogAnalyzer

输出结构化 `WanStatus`，包含 WAN 接口/IP、模组、固件、SIM、注册、附着、CSQ/RSRP/RSRQ/SINR、APN、PPP/LCP/IPCP、错误标志等。

兼容：

```text
MAIN LINK Q:/A:
4G_MAIN_Q:/A:
[name= xxx data= yyy ]
[data=wan_ipaddr value=x.x.x.x]
+CPIN:
+CGREG:
+C5GREG:
+CREG:
+CGATT:
+CSQ:
+CME ERROR:
```

### 4.4 DiagnosisEngine

优先级：模组未识别、SIM 异常、注册被拒绝、弱信号注册失败、数据附着失败、蜂窝 PPP/IPCP 地址协商失败、DHCP 失败、PPPoE 失败、物理链路断开、上层 WAN IP 未更新、WAN 正常、未知。

约束：

- 不把任意 `+CME ERROR` 直接视为致命模组错误。
- `+CME ERROR` 必须关联到 AT 命令、重复次数和后续链路状态。
- 蜂窝 PPP (`ATD*99#`) 与 PPPoE 分开判定。
- `attach_check: status = 0` 仅作辅助信息，不等价于 `CGATT: 0`。

## 5. PCAP 实时流设计

默认命令：

```sh
exec tcpdump -i <wan_ifname> -U -s 0 -w -
```

可追加 BPF 过滤器，例如：

```sh
exec tcpdump -i usb0 -U -s 0 -w - 'tcp port 2404'
```

### 5.1 Telnet 二进制处理

- `FF FF` → 原始数据 `FF`
- `FF FB xx` / `FF FC xx` / `FF FD xx` / `FF FE xx` → Telnet 协商，不进入 PCAP
- 必须处理跨 `readyRead()` 分片的 IAC 序列

PCAP 数据不能直接使用未解码的 `QTcpSocket::readAll()`。

### 5.2 PcapStreamReader

维护 `QByteArray m_buffer`，依次解析 24 字节 Global Header、16 字节 Packet Header、`incl_len` 字节数据。

必须支持：

- little/big endian Classic PCAP
- microsecond/nanosecond timestamp
- 分片输入
- 异常 `incl_len` 防护

首版不支持 PCAPNG。

### 5.3 PacketParser

首版解析 Ethernet、Linux cooked capture v1、RAW IP、IPv4、TCP、UDP、ICMP。

### 5.4 PacketAnalyzer

实时统计总包数/总字节、TCP/UDP/ICMP、SYN/RST/FIN、疑似 SYN 无响应、疑似 TCP 重传、ICMP request/reply、Top endpoint、Top conversation。启发式项明确标为“疑似”。

## 6. 停止抓包

优先通过 Control Telnet 查询：

```sh
pidof tcpdump
```

再执行：

```sh
kill -2 <pid>
```

若 `pidof` 不可用，则 `ps | grep '[t]cpdump'`；最后兜底使用 `killall tcpdump`。GUI 另提供强制断开抓包连接。

## 7. 本地 PCAP 导出

路由器端始终不保存文件。

- 短时诊断：原始 PCAP 字节保存在 PC 内存，用户点击“导出 PCAP”后写本地文件。
- 长时抓包：用户勾选“同时保存 PCAP”时，PC 端直接写 `QFile`，避免内存持续增长。

## 8. GUI

连接参数：Router IP、Telnet Port、Username、Password、WAN Interface（自动获取/可覆盖）。

WAN 诊断区显示模组、SIM、注册、信号、APN、PPP、WAN IP、结论和建议。

抓包区包含 BPF filter、开始/停止、导出 PCAP、保存目录、抓包时长、包数和数据量。

包表：No. / Time / Source / Destination / Protocol / Length / Info。

## 9. 工程结构

```text
WanDiagTool/
├─ CMakeLists.txt
├─ main.cpp
├─ MainWindow.h/.cpp/.ui
├─ telnet/TelnetClient.h/.cpp
├─ diagnostic/DiagnosticTypes.h
├─ diagnostic/DiagnosticController.h/.cpp
├─ diagnostic/LogAnalyzer.h/.cpp
├─ diagnostic/DiagnosisEngine.h/.cpp
├─ capture/PcapTypes.h
├─ capture/PcapStreamReader.h/.cpp
├─ capture/PacketParser.h/.cpp
├─ capture/PacketAnalyzer.h/.cpp
├─ capture/PacketCaptureController.h/.cpp
├─ report/ReportExporter.h/.cpp
└─ docs/superpowers/specs/2026-08-28-wan-diag-tool-design.md
```

## 10. 错误处理

显式处理 Telnet 连接/登录失败、shell prompt 不识别、命令超时、tcpdump 不存在、接口不存在、权限不足、抓包断线、非法 PCAP magic、长度异常、数据截断、本地写文件失败。所有错误通过 signal/状态栏输出，不阻塞 GUI。

## 11. 测试

单元测试重点：Telnet IAC decoder、PCAP 分片解析/endian、AT 命令上下文解析、PPP/IPCP 判定、成功/失败拨号日志回归。

样本回归使用用户上传的 `23.8拨号成功.txt`、`26.1拨号不上.txt` 和 PuTTY/tcpdump 抓包日志。

实机最终验证 Telnet 登录提示符、`tcpdump -w -`、link type、停止 PID 策略和长时间稳定性。

## 12. 第一版明确不做

PCAPNG、IPv6 深度解析、TLS 解密、Wireshark dissector 等价能力、Npcap 本机抓包、SSH/SCP、多路由器并行抓包、插件系统。
