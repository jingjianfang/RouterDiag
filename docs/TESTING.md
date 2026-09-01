# WanDiagTool v1.2 测试与现场验证

## 1. Windows / Qt 6.8.3 全量构建

从 **Visual Studio 2022 Developer Command Prompt** 进入工程根目录，一行一条执行：

```bat
cmake -S . -B out\build\debug -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="C:\Qt\6.8.3\msvc2022_64"
cmake --build out\build\debug --config Debug
```

测试 EXE 为 Debug Qt 构建时，先设置：

```bat
set PATH=C:\Qt\6.8.3\msvc2022_64\bin;%PATH%
```

然后执行完整测试：

```bat
ctest --test-dir out\build\debug -C Debug --output-on-failure
```

如果测试 EXE 直接以 `0xc0000135` 退出，先执行：

```bat
dumpbin /dependents out\build\debug\tests\Debug\test_loganalyzer.exe | findstr /I "Qt6"
where Qt6Cored.dll
```

`0xc0000135` 通常表示运行时 DLL 不在当前 PATH；它不是测试断言失败。

## 2. 单元测试覆盖范围

当前 CTest 目标包含：

- `test_telnetdecoder`：Telnet IAC/二进制转义。
- `test_pcapstreamreader`：Classic PCAP 分片、大小端、非法 magic。
- `test_packetparser`：IPv4/TCP/UDP/ICMP、TCP payload、IPv4 Total Length、截断保护。
- `test_packetanalyzer`：协议统计、TCP 基础状态和疑似重传。
- `test_loganalyzer`：SIM、网络注册、WAN、DTS、PPP/IPCP 上下文分析。
- `test_diagnosisengine`：模组/SIM/注册/WAN 分层根因。
- `test_offlinepcapcontroller`：离线 PCAP 自动分析和回放。
- `test_iec104analyzer`：IEC104 APDU/I/S/U 帧识别。
- `test_iec101analyzer`：IEC101 固定/可变帧识别。
- `test_gridsecurityanalyzer`：国网安全/加密外层和当前样本基线序列。
- `test_protocoldiagnosis`：IEC101/104 与国网安全层组合，不伪解密。
- `test_reportexporter`：六层报告渲染/导出。
- `test_connectivityprobe`：IPv4 输入校验与 Ping 输出解析。
- `test_channelanalyzer`：主站握手、140 字节 IPv4 ICMP、业务 TCP 通道证据。
- `test_fielddiagnosticcontroller`：主站/终端现场命令编排与安全 BPF。
- `test_mainwindowui`：`admin/admin`、2404、网口/串口切换和六层报告 UI。

## 3. v1.1 回归检查

### 3.1 离线 WAN 日志

主界面点击 **导入系统日志**，分别导入：

```text
samples/demo_wan_ok.log
samples/demo_wan_ipcp_fail.log
```

确认原有成功/IPCP 失败分类仍可生成诊断结果。

### 3.2 离线 PCAP

导入：

```text
samples/demo_capture.pcap
```

检查：

1. 自动快速分析完成。
2. TCP/UDP/ICMP 包仍进入包列表和统计。
3. 1x/5x/10x/最快回放仍可启动。
4. 停止回放仍有效。

## 4. v1.2 日志分层回归

测试 fixture：

```text
tests/fixtures/sim_not_detected.txt
tests/fixtures/registration_failed.txt
tests/fixtures/normal_cellular_and_dts.txt
```

预期：

### SIM 未识别

- ATI/模组响应证据存在时，不能判定“模组失联”。
- `AT+CPIN? -> ERROR` 与 `sim_card` 为空应落到 SIM 层。
- WAN `0.0.0.0` 是后续结果，不应覆盖 SIM 根因。

### 注册失败

- `+CPIN: READY` / `simok` 时 SIM 层应正常。
- 持续非成功的 CEREG/CGREG/C5GREG 应落到注册层。
- `Network is unreachable` 与 WAN `0.0.0.0` 作为后续链路证据。

### 正常蜂窝/DTS

- 有效 `wan_ipaddr` / `wanface` 应被识别。
- `attach_check: status=0` 不能单独否定已有有效 WAN IP。
- `serial1 baudrate` 只表示串口配置存在。
- 如果同时出现 `south tcp client config connect` 和 `tcp client connect ok`，当前实际终端通道证据应落到 TCP/网口方向。

## 5. 业务数据（国网加密/IEC）协议回归

Fixture：

```text
tests/fixtures/grid_security_normal.txt
tests/fixtures/grid_security_repeated_56.txt
```

检查：

- `EB...D7` 识别为国网安全/加密外层证据，而不是直接标成 IEC104。
- 当前正常样本中的 `80 20 -> 80 21 -> 80 22 -> 80 23` 可作为完整交互证据。
- `50/51` 可作为当前样本正常基线的一部分。
- 重复 `0x56` 只在满足当前基线判据时报告“偏离正常样本/异常趋势”，不能写成通用标准意义上的“非法命令”。
- 如果加密 payload 不可见，第 7 层必须保持“不足以确认内部 IEC101/IEC104”。

## 6. 无设备 GUI Smoke Test

启动：

```bat
out\build\debug\Debug\WanDiagTool.exe
```

检查默认值：

```text
用户名：admin
密码：admin
业务端口：2404
终端通讯：网口
```

检查网口模式：

- 终端 IP 可输入。
- `Ping终端` 可用。
- `抓终端 br0` 可用。
- 文案说明 Ping 成功后使用 `br0 host <终端IP>`。

切换到串口模式：

- 终端 IP 禁用。
- `Ping终端` 禁用。
- `抓终端 br0` 禁用。
- 提示应说明依据 DTS/systemlog 证据判断。
- 不得把 `/dev/ttyUSB*` 作为终端串口默认路径。

检查六层区域包含：

```text
[1] 模组/AT
[2] SIM
[3] 蜂窝注册
[4] WAN/IP
[5] 主站与终端链路
[6] 业务数据
```

## 7. 有设备现场验证

### 7.1 主站

填写主站 IP 和实际端口，依次验证：

1. Ping 主站。
2. 抓主站。
3. 抓包同时包含主站 ICMP 与业务 TCP。
4. 能观察 SYN/SYN-ACK/ACK、PSH-ACK、RST/FIN 等证据。
5. 现场存在文档所述探测报文时，检查 140 字节判断基于 IPv4 Total Length。

### 7.2 终端网口

1. 选择网口。
2. 填终端 IP。
3. Ping 终端。
4. Ping 成功后检查 `br0 host <终端IP>` 抓包。
5. 确认不会把用户输入未经 IPv4 校验直接拼进 shell/BPF。

### 7.3 终端串口

当前仅验证 DTS/systemlog 中的串口配置和收发证据。实际外部终端串口主动探测需要先拿到具体硬件设备节点/驱动映射和现场日志，再增加对应适配器。

## 8. 安全/架构检查

发布前检查：

```bat
findstr /S /N /I "nvram set nvram commit" diagnostic\*.cpp diagnostic\*.h
findstr /S /N /I "ttyUSB" diagnostic\*.cpp diagnostic\*.h MainWindow.cpp MainWindow.ui
```

预期：

- 自动诊断代码中没有 `nvram set`/`nvram commit`。
- `ttyUSB` 若出现，只能用于说明“模组控制口证据，不是终端串口”。

在线抓包仍必须保持二进制 PCAP stdout 流方式：

```text
tcpdump -i <interface> -U -s 0 -w - <BPF>
```

路由器侧不创建 PCAP 文件。

## 9. 已知非阻塞警告

如果 Windows 启动时看到：

```text
libpng warning: tRNS: invalid with alpha channel
```

但主界面正常显示、测试全部通过，这属于当前环境/图标加载路径产生的 PNG 元数据警告，不影响 WAN/抓包/协议分析逻辑。若后续需要做发布版 UI 资源清理，可单独定位图标来源后处理。

## v1.2 Batch 8 - UI 收敛与一键现场诊断

Windows / VS2022 / Qt 6.8.3：

```cmd
cmake --build out\build\debug --config Debug --target test_fieldworkflowcontroller test_mainwindowui WanDiagTool
ctest --test-dir out\build\debug -C Debug -R "test_fieldworkflowcontroller|test_mainwindowui" --output-on-failure
```

重点人工检查：

- 主界面只有 `现场诊断 / 实时抓包 / 离线分析 / 工具` 四个主要页签；
- 未连接时一键诊断、WAN诊断、Ping、抓包按钮保持禁用；
- 连接并完成双 Telnet 登录后“一键现场诊断”可用；
- 网口终端模式的一键顺序为：接口检测 → WAN诊断 → Ping主站 → 主站抓包 → 重建抓包Telnet → Ping终端 → Ping成功后 `br0 host <终端IP>` 抓包；
- 串口终端模式不会执行终端 IP Ping / br0 抓包；
- 停止一次 tcpdump 后抓包 Telnet 会自动重建，可继续第二段抓包；
- 六层状态表选择行后，右侧“当前层”显示证据、结论和建议；
- 数据包表选择行后显示 TCP/ICMP 字段、Payload HEX 和可识别的 IEC/国网安全信息。


## Batch23 模组 AT 自动识别

- 登录后自动扫描 `/dev/ttyUSB*` / `/dev/ttyACM*`，优先采用 systemlog 中的 `CONTROL DEVICES`。
- `at_test` 可用时优先使用；不可用或没有正常 `OK` 时退回直接设备读写。
- 查询顺序：`ATI` → `AT+CGMI` → `AT+CGMM` → `AT+CGMR`。
- 直接读写必须主动回收后台 `cat` 进程。
- 独立契约：`cmake -P tests/batch23_module_probe_contract.cmake`。
