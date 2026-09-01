# 四信路由器通信诊断工具 — RC13 Batch45

面向嵌入式路由器、工业网关和 CPE 的 VS2022 + Qt C++ 现场诊断工具。通过独立 Telnet 控制/抓包通道完成 WAN、主站、终端和国网 101/104 通讯链路的分层诊断。

## v1.2 核心能力

- **默认登录**：用户名 `admin`、密码 `admin`。
- **路由器端不保存 PCAP**：在线抓包使用 `tcpdump -U -s 0 -w -`，Classic PCAP 从 stdout 直接流回 PC。
- **Telnet 二进制安全**：处理 IAC (`0xFF`) 转义与 WILL/WONT/DO/DONT 协商后再交给 PCAP 解析器。
- **在线 + 离线共用分析链**：在线 tcpdump 和离线 PCAP 共用 `PcapStreamReader -> PacketParser -> PacketAnalyzer/ProtocolDiagnosis`。
- **模组自动识别**：路由器登录后自动确认 AT 控制口并查询 `ATI`、`AT+CGMI`、`AT+CGMM`、`AT+CGMR`；优先使用 `at_test`，不可用或无有效 `OK` 时安全回退到直接读写 `/dev/ttyUSB*`/`/dev/ttyACM*`。
- **六层现场诊断**：模组/AT、SIM、蜂窝注册、WAN/IP、主站与终端链路、业务数据。业务数据层统一分析普通 IEC101/104 与国网加密101/104。
- **主站诊断**：填写主站 IP 和业务端口（默认 `2404`），支持 Ping、主站抓包、TCP 三次握手、RST/FIN、PSH-ACK、140 字节 IPv4 ICMP 证据分析。
- **终端网口诊断**：填写终端 IP 和终端端口（默认 `2404`）；Ping 仅作为辅助证据，即使 ICMP 未应答，一键诊断仍继续在 `br0` 抓取 `host <终端IP> and (icmp or tcp port <终端端口>)`，用于判断 TCP 超时、拒绝、握手、RST/FIN 和数据方向。
- **终端串口诊断**：根据 DTS/systemlog 中的实际配置和收发证据判断；不会把模组的 `/dev/ttyUSB*` 当作外部终端串口。
- **IEC104**：识别 APDU、I/S/U 帧和 STARTDT/STOPDT/TESTFR 等可见控制信息。
- **IEC101**：独立识别固定帧和可变帧，不套用 IEC104 解析逻辑。
- **国网安全/加密交互**：识别 `EB...D7` 外层交互和当前现场样本中的会话序列证据；不在没有密钥时伪装解密。
- **精细日志诊断**：区分“模组 AT 正常但 SIM 未识别”“SIM 正常但网络注册失败”“已注册但 WAN/IP 未建立”等不同故障层级。
- **报告导出**：保存当前六层综合诊断结果和证据。
- **宽松型现场 UI**：设备状态使用摘要卡片；网口详情、抓包高级 BPF、实时运行日志默认折叠，需要时再展开，减少首屏拥挤。
- **模块日志本地留存**：模块实时日志默认边看边保存到 `文档\FourFaith_RouterDiag\logs`；界面只保留最近约 5000 行，文件持续完整写入，并支持打开目录/另存为。
- **自定义快捷指令**：命令窗口可新增、编辑、删除自己的备用命令并使用 `QSettings` 持久保存；`nvram set/commit`、`reboot`、危险 `rm` 等命令执行前二次确认。

## 环境

已验证的目标环境：

- Visual Studio 2022 x64
- Qt 6.8.3 `msvc2022_64`
- CMake 3.20+
- C++17
- 路由器具备 Telnet、shell 和 tcpdump

Qt 5.15.x/其他 Qt 6.x 仍保留兼容写法，但 v1.2 主要联调环境为 Qt 6.8.3。

不依赖 Python、Npcap、WinPcap 或 libpcap。

## VS2022 + Qt 6.8.3 构建

建议从 **Visual Studio 2022 Developer Command Prompt** 执行，一行一条：

```bat
cmake -S . -B out\build\debug -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="C:\Qt\6.8.3\msvc2022_64"
cmake --build out\build\debug --config Debug
```

Debug 测试运行前，确保 Qt Debug DLL 在 `PATH`：

```bat
set PATH=C:\Qt\6.8.3\msvc2022_64\bin;%PATH%
ctest --test-dir out\build\debug -C Debug --output-on-failure
```

运行程序：

```bat
out\build\debug\Debug\WanDiagTool.exe
```

需要复制 Qt 运行库到可分发目录时可使用：

```bat
C:\Qt\6.8.3\msvc2022_64\bin\windeployqt.exe --debug out\build\debug\Debug\WanDiagTool.exe
```

## 现场使用流程

### 1. 连接路由器

输入路由器 IP 和 Telnet 端口。默认：

```text
用户名：admin
密码：admin
端口：23
```

点击 **连接**。

### 2. WAN/蜂窝诊断

点击 **诊断 WAN**。工具采集只读诊断信息并解析系统日志，重点区分：

```text
模组/AT
    ↓
SIM 卡识别
    ↓
蜂窝网络注册
    ↓
WAN / IP / PPP/IPCP
```

自动诊断流程不会执行 `nvram set` 或 `nvram commit`。

单条通用 `ERROR`、`+CME ERROR` 或 `attach_check: status=0` 不会单独作为最终故障结论；会结合对应 AT 命令、CPIN、注册状态、WAN IP 和业务链路形成证据链。

### 3. 主站诊断

填写：

```text
主站 IP：现场实际主站地址
业务端口：2404（可修改）
```

可以 Ping 主站，也可以点击 **抓主站**。主站抓包 BPF 会同时保留 ICMP 和业务 TCP，例如：

```text
host 90.15.80.82 and (icmp or tcp port 2404)
```

这样可以同时分析现场流程中“140 字节 IPv4 ICMP”证据和 TCP SYN/SYN-ACK/ACK/PSH-ACK。

> 140 字节判断使用 IPv4 Total Length，不直接用以太网 PCAP 的 captured length。

### 4. 终端网口诊断

选择 **网口**，填写终端 IP 和终端端口：

1. 点击 **Ping终端**，把 ICMP 可达性作为辅助证据。
2. 不论 Ping 是否应答，都可以继续抓取终端业务 TCP；一键诊断也不会因 ICMP 被禁用而提前停止。
3. 抓包接口固定使用 `br0`，过滤器同时保留 ICMP 和指定终端业务端口。

实际命令形态类似：

```sh
exec tcpdump -i br0 -U -s 0 -w - 'host 192.168.3.102 and (icmp or tcp port 2404)'
```

TCP 会话会按 `IP:端口` 分开分析，可区分三次握手成功、连续 SYN 无应答、RST 拒绝连接、握手不完整、FIN 正常关闭、RST 异常重置、单向或双向 Payload，并在结论中指出具体主动方/目标端。

### 5. 终端串口诊断

选择 **串口** 后，终端 IP、Ping 和 `br0` 抓包入口会禁用。

v1.2 的串口诊断依据 DTS/systemlog 中可见的：

```text
serial1 baudrate
数据位/停止位/校验/流控
DTS 启动状态
终端/装置方向的收发证据
```

**不会使用 `/dev/ttyUSB0`、`/dev/ttyUSB2` 等作为终端串口默认值。** 这些路径在当前日志中属于模组 AT/control device 证据。

此外，“日志中存在 `serial1 baudrate` 配置”不等于“当前实际正在走串口”。如果同时观察到 `south tcp client config connect`、`tcp client connect ok` 等证据，工具会把当前观察到的终端通道判断为 TCP/网口方向。

## 国网 101/104 与加密通讯分析

v1.2 在六层报告中把普通 IEC101/104 与国网加密 101/104 统一归入第 6 层“业务数据”，但内部仍区分传输链路、安全/加密外层和可见的 IEC 业务内容，避免把不同层级混为一谈：

```text
主站/终端 TCP 传输链路
        ↓
可选的国网安全/加密外层
        ↓
可见时识别 IEC60870-5-101 / IEC60870-5-104
```

### 普通 IEC104

在 TCP Payload 可见时识别 IEC104 APDU，并解析可见的 I/S/U 帧与 STARTDT/STOPDT/TESTFR 控制信息。

### 普通 IEC101

独立识别 IEC101 固定帧和可变帧。IEC101 与 IEC104 使用不同解析器。

### 国网加密 101/104

`EB...D7` 按“国网安全/加密交互外层证据”处理，不直接等同于 IEC101/104 业务数据。

当前现场样本中的 `80 20/21/22/23`、`50/51`、重复 `56` 等序列只作为**当前样本基线**和异常趋势证据，不宣称它们是所有国网加密设备/版本的标准固定语义。

如果负载已经加密且工具没有密钥，报告会明确写“加密业务内容不可见/无法确认内部 101 或 104”，不会输出伪解密结果。

## 离线分析（无需路由器）

主界面 **离线分析（无需路由器）** 支持：

- **导入系统日志**：直接走与在线诊断相同的 `LogAnalyzer + DiagnosisEngine`。
- **导入 PCAP**：支持 Classic `.pcap/.cap`，自动快速分析。
- **回放 PCAP**：`1x / 5x / 10x / 最快`。
- **停止回放**：可以中断离线回放。

在线和离线共用同一套 packet/protocol 解析路径，便于无设备阶段回归。

### 自带样本

`samples/` 中包含：

```text
samples/demo_wan_ok.log
samples/demo_wan_ipcp_fail.log
samples/demo_capture.pcap
```

`tests/fixtures/` 另外包含 v1.2 的 SIM 未识别、注册失败、正常蜂窝/DTS 和国网安全交互测试样本。

## 六层报告含义

界面“现场诊断”按以下六层顺序输出：

```text
[1] 模组/AT
[2] SIM
[3] 蜂窝注册
[4] WAN/IP
[5] 主站与终端链路
[6] 业务数据
```

每层尽量采用：

```text
状态 / 置信度
证据
结论
建议
```

“尚未形成完整诊断证据”表示当前没有足够输入，并不表示该层故障。

## 辅助工具

“工具”页中的模块日志、命令/快捷指令和 Ping 都使用独立 Telnet 会话，不占用主诊断控制通道。

- **模块日志**：路由器控制 Telnet 登录成功后会用独立日志 Telnet 先读取 `nvram get debuglog_enable`；先确保 `debuglog_enable=1`（每次 set 后执行 `nvram commit`），网口 Telnet 日志再确保 `syslogd_enable=3` 并提交，随后执行 `tail /tmp/.systemlog -f`。打开“模块日志”窗口时默认自动保存到 PC 文档目录，并实时提取模组、SIM、注册、RSRP/RSRQ/SINR、WAN 和终端信息。
- **快捷指令**：使用“分类 / 名称 / 命令 / 备注”四列表格管理，并支持分类筛选、搜索和 JSON 导入/导出。单击快捷指令会自动填入“执行命令”，双击可直接执行；现场人员可以新增、编辑、删除自己的快捷指令并永久保存。
- **安全提示**：手工命令窗口允许高级用户执行修改类命令，但高风险命令会弹出二次确认。一键诊断流程自身仍不写 NVRAM；当前自动日志配置仅按需设置 `debuglog_enable=1`，网口 Telnet tail 场景再按需设置 `syslogd_enable=3`，每次 set 后均执行 `nvram commit`。

## 重要限制

- 当前只解析 **Classic PCAP**，不解析 PCAPNG。
- “疑似重传”“SYN 无响应”等仍属于轻量启发式，不等同 Wireshark Expert Info。
- Telnet 登录提示符和 shell 输出在不同固件中可能不同，首次实机需要验证。
- 某些 tcpdump 版本可能不支持 `-U`，现场可按固件能力调整。
- 当前支持 Ethernet、Linux cooked v1 和 RAW IPv4；其他 PCAP link type 可能显示 unsupported。
- **终端串口主动探测尚未实现**：在提供实际路由器外部终端串口设备映射和更多现场日志前，v1.2 只根据 DTS/systemlog 证据判断。
- **不会在没有密钥时解密国网加密业务负载。**
- **80xx/50xx/56 等比较是当前现场样本基线，不是协议标准语义声明。**
- **一键诊断流程自身不修改 NVRAM；连接后自动模组日志会按需设置并提交 `debuglog_enable=1`；网口 Telnet tail 场景同时按需设置并提交 `syslogd_enable=3`。**

详细回归步骤见 `docs/TESTING.md`。

## v1.2 现场工作流（UI 收敛版）

主界面按用途分为四个页签：`现场诊断 / 实时抓包 / 离线分析 / 工具`。路由器连接成功后保持待机，不自动启动 WAN/SIM/模组检测；点击“一键现场诊断”后才开始有限次数的设备检测。主站和终端 IP 会保留最近使用记录用于补全。

“一键现场诊断”按以下顺序执行（自动流程只读设备配置）：

1. 自动读取 WAN 接口和 WAN/SIM IP；
2. 分析模组、SIM、网络注册和 WAN/IP；
3. Ping 主站；
4. 在实际 WAN 接口抓取 `host <主站IP> and (icmp or tcp port <业务端口>)`，同时观察 140 字节 ICMP、TCP 建链和业务 Payload；
5. 终端为网口时 Ping 终端，并无论 Ping 是否应答都继续抓取 `br0` 上 `host <终端IP> and (icmp or tcp port <终端端口>)`；终端为串口时跳过 IP/`br0`，依据 DTS/systemlog 的实际南向收发证据判断；
6. 将国网安全/加密交互与 IEC101/IEC104 统一汇总到“业务数据”层，输出六层报告。

自动抓包每段默认 8 秒，可在现场诊断页调整。自动流程抓包保存在内存，避免一键流程中弹出文件选择框；结束后可在“实时抓包”页手工导出 PCAP。

抓包连接由于 `tcpdump -w -` 使用二进制 Telnet 流，停止一次抓包后会重建独立抓包 Telnet 会话，以支持同一轮诊断连续执行“主站抓包 → 终端 br0 抓包”。

### v1.2 离线文本抓包转换

- **tcpdump 文本 → PCAP**：支持 PuTTY/tcpdump `-xx/-XX` 日志中的 `0x0000/0x0010...` 完整十六进制帧恢复；完整包写入 Classic PCAP，缺失字节的包只报告并跳过，不伪造数据；转换后自动进入现有离线 PCAP 分析。


### v1.2 实时抓包分析增强

- “开始抓包”先检查 `tcpdump`、抓包接口和 BPF，界面直接显示“正在检查 / 等待 PCAP 头 / 运行中 / 启动失败”，避免失败只藏在运行日志里。
- 实时抓包下方提供 `包详情 / Payload / HEX / TCP 会话 / 业务解析`，可勾选“跟随最新报文”。
- TCP 会话按 `IP:端口` 分析三次握手、SYN 无应答、RST 拒绝、异常重置、FIN 关闭、单向/双向 Payload；离线 PCAP 回放复用同一分析视图。
- 蜂窝实时状态支持从日志提取 CSQ/RSSI、RSRP、RSRQ、SINR；没有证据的字段保持未知，不根据单一指标武断判断网络注册原因。

## v1.2 单文件发布

开发机执行 `package_onefile_release.bat` 可生成 `dist\FourFaith_RouterDiag_v1.2.exe`。这是单文件自解压发布包：目标 Windows 10/11 x64 电脑无需安装 Qt 或 Visual Studio；运行时会把私有 Qt/MSVC 运行环境释放到临时目录并启动应用。详细说明见 `docs/DEPLOYMENT.md`。

## Batch 16: compact responsive UI + realtime module log

- Main window can shrink to 900x600. Below 1180px the connection/status/capture controls reflow; a scroll-area fallback prevents overlap on smaller displays.
- Product title uses a smaller 20px heading.
- Module-log viewer runs `tail /tmp/.systemlog -f` and refreshes the raw Telnet stream every 50ms without inserting fake line breaks between TCP chunks.
- Module log is still auto-saved and live-parsed for module/SIM/registration/WAN/RSRP/RSRQ/SINR evidence.

## Batch 17 maintenance note
The ReportExporter repeated-0x56 regression test now checks conservative semantics (sample baseline + mismatch + no illegal-command claim) instead of one exact Chinese sentence, preventing wording-only changes from causing false test failures.

## Parser / diagnostics hardening (Batch30-32)

- Structured AT registration parsing for CEREG/CGREG/CREG/C5GREG, including reject causes and extended registration states 6-10.
- Active AT telemetry now includes CGATT, CSQ and COPS in addition to SIM/registration queries.
- `tcpdump -i any` text fallback supports Ethernet/VLAN/QinQ, Linux SLL/SLL2 and RAW IP recovery.
- TCP retransmission detection counts payload-bearing duplicate segments only; RST clears pending SYN state.
- TCP diagnosis selects the current/main business session and reports older failed attempts separately.
- Live system-log current failure flags are derived from a bounded recent window while historical event counters remain cumulative.
- Telnet command execution uses unique completion markers and strips echoed wrapped commands from parser input.
- Dual-point capture correlates payloads across LAN/WAN using TCP sequence, length and payload hash and reports cross-side timing.
- IEC104 session analysis tracks STARTDT/STOPDT/TESTFR, N(S)/N(R), gaps/duplicates and bounds outstanding-I estimates to frames actually observed.
- Long captures stream PCAP to a temporary file; realtime tables retain only the most recent 20,000 rows.
- Protocol stream analysis is coalesced (200 ms) and TCP reassembly state is reset between capture/replay sessions.

## Batch41：1280 分辨率布局优化
- 1280px 宽窗口使用紧凑响应式布局；1440px 及以上保持宽屏布局。
- 修复现场参数控件在响应式重排后残留旧几何位置的问题。
- 每段抓包与连接等待移动到“高级参数”；当前层完整详情按需展开。
- compact 模式优化诊断面板比例、数字输入框和悬浮标题栏占用。


## RC13 Batch42
WAN接口检测排除 br0/LAN bridge；无可信接口时保持“未检测到”。同时修复1280响应式重排后工作区模式选择器脱离连接区布局的问题。终端LAN侧抓包仍使用 br0。

## RC13 Batch43
- “新建抓包任务”移到实时抓包报文面板标题栏，抓包参数区不再被额外按钮占行。
- 终端通讯为串口时自动隐藏终端IP/端口/角色/Ping；切回网口自动恢复。
- 现场诊断高级参数（每段抓包、连接等待）始终显示。
- 快捷指令补充 reboot、进程/系统、主备WAN、TCP监听、模组/信号和抓包接口等现场常用命令；危险命令继续二次确认。


## RC13 Batch44
- “布局”更名为“工作视图”，选项调整为“诊断视图 / 抓包视图 / 双屏视图”。
- 切换工作视图不再改变连接区折叠状态；连接区是否展开只由用户手动控制。
## Batch45 现场抓包增强

- 全接口可编辑选择，支持 VPN `tun0/tap0`、蜂窝、VLAN、bridge 和 `any`。
- 新增自定义抓包、接口刷新和明显的“新建抓包窗口”入口。
- 串口终端模式将串口日志、网络抓包和串口与网络时间线分类展示。
- 1280 宽度连接区避免长状态文字覆盖；工具快捷指令改用更通俗的显示名称。

详见 `README_BATCH45.txt`。

## RC13 Batch46
- 修复 Batch45 Windows 编译时残留 `ui->editIface` 导致的 C2039：抓包接口选择器直接复用 `MainWindow.ui` 中的可编辑下拉框和刷新按钮。
- 用户自定义快捷命令优先于同名内置项加载，避免“查看进程 / ps”等同名命令被内置项遮蔽；内置 `ps`、`reboot` 仍保留。
- 新增 Batch46 回归合同；Windows 动态回归目标为 60 tests。

详见 `README_BATCH46.txt`。

## RC13 Batch47
- 同步 Batch45/46 后的抓包 UI 单元测试：可编辑接口下拉框 + 4 种抓包模式。
- 清理 DetachablePanelManager 的 QSplitter::replaceWidget sibling 警告。
- 不改 WAN/抓包/诊断逻辑；Windows 动态回归目标为 61 tests。

详见 `README_BATCH47.txt`。


## RC13 Batch48
- 删除冗余“工作视图”，直接使用 `现场诊断 / 实时抓包 / 离线分析 / 工具` 四个页签。
- 实时抓包控制区收口：目标 IP/端口按模式显示，抓包过滤条件保持直接可编辑，“新建抓包窗口”固定在报文面板标题栏。
- 抓包接口下拉只列路由器 `ifconfig` 实际返回的接口；不再自动塞入 `any` 或猜测接口，但仍允许手工输入 `tun0 / any / 其它接口`。
- 修复 BusyBox `ifconfig` 解析把 `collisions:`、`Interrupt:` 误当接口的问题。
- 连接成功后不再自动检测，也不自动启动后台模组日志分析；只有用户主动开始诊断后才收集诊断证据。若有限 WAN 清单检查仍未识别到可信 WAN，立即结束自动检测，不继续模组 AT 探测。
- 一键诊断运行时在状态栏提供跨页可见的“停止诊断”，切到抓包/离线/工具页仍可停止。
- 1280 级宽度下重新约束连接区布局，串口/网口状态切换后不再挤压覆盖。
- 设备状态卡使用 `正常 / ERROR / 未识别 / 未测试` 等简短状态；SIM/网络注册不再显示原始 `READY` 等 AT 文本，模组型号/固件放到详情/提示。WAN 接口/IP 与信号数值仍保留必要的现场信息。

详见 `README_BATCH48.txt`。

## RC13 Batch49
- 离线抓包导入支持 `.pcap / .cap / .pcapng`，并按内容识别 Classic PCAP/PCAPNG。
- 离线入口只保留“导入日志”，不再从主界面导入 `.bin` 配置快照。
- Windows EXE、窗口和任务栏使用新的路由器通信诊断应用图标。

## RC13 Batch50
- 修复 Batch49 图标链路：Qt 运行时改用内嵌 PNG，不再依赖精简包中被删除的 imageformats/icon 插件目录。
- 主窗口显式继承 QApplication 图标，标题栏与任务栏使用同一套路由器通信诊断图标。
- 原生 `WanDiagTool.exe` 继续通过 `.rc` 嵌入多尺寸 ICO；IExpress 最终单文件外壳在生成后、计算 SHA256 前再写入同一套 ICO。
- 新增 Windows 资源写入脚本 `packaging/set_exe_icon.ps1` 和 Batch50 图标链路回归合同；不改 WAN、诊断、抓包和离线分析业务逻辑。

详见 `README_BATCH50.txt`。

## Batch55 - refresh interface UP-only consistency
- Manual `刷新接口` now explicitly keeps only interfaces parsed as `UP` from ordinary `ifconfig` output.
- The interface detail table and capture-interface dropdown are rebuilt from the same UP-only list.
- Added `tests/batch55_refresh_up_filter_contract.cmake` to keep manual refresh and automatic discovery consistent.


## RC13 Batch56
- WAN、模组、SIM、注册和信号优先使用批量 `nvram get` 快速读取；`this_is_bkup=1` 时优先备卡 `bkup_*`，缺失项再回退实时 `comm_*` / AT。
- 网口详情和抓包真实接口仍严格来自普通 `ifconfig` 且只显示 UP；`any` 仅作为 tcpdump“所有接口”伪接口。
- WAN/主站/终端抓包模式自动对应接口；同步抓包不再额外刷新接口抢占 Telnet，串口控制模式合并为单个 `tcpdump -i any`。
- 所有用户可见命令输出统一清理命令回显、`__FF_CMD_DONE_*`、wrapper 和 shell 提示符。
- PCAP/CAP/PCAPNG/PAP 大文件改为分块导入并直接分析显示，表格最多保留最近 20,000 包；超过 64 MiB 不缓存整份回放数据。

详见 `README_BATCH56.txt`。
- 终端网口检测会用普通 `ifconfig` 中 `br0/br0:1` 的 IPv4+掩码校验终端 IP 网段；不在任一 LAN 网段时直接提示配置错误并停止终端检测。
