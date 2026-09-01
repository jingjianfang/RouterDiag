RC13 Batch49 - 离线导入与应用图标整理

1. 离线抓包导入
- 文件选择支持 .pcap / .cap / .pcapng。
- .pcap 与 .cap 继续按 Classic PCAP 内容解析。
- 新增 PCAPNG 内容识别与解析：Section Header、Interface Description、Enhanced Packet Block；不是只按扩展名判断。
- 支持 Ethernet / Linux SLL / Linux SLL2 / Raw 链路类型（由现有 PacketParser 能力决定）。

2. 离线日志
- “导入日志/配置”改为“导入日志”。
- 文件选择只显示 .txt / .log，不再开放 .bin 配置快照导入。
- NVRAM 快照解析器代码仍保留用于历史兼容和独立测试，但主界面不再提供配置文件导入入口。

3. Windows 应用图标
- 新增原创路由器通信诊断图标，多尺寸 ICO。
- Windows EXE 通过 app_icon.rc 嵌入文件图标。
- Qt 资源通过 app_icon.qrc 加入程序，并在 QApplication 设置窗口/任务栏图标。

4. 回归
- 新增 PCAPNG Enhanced Packet Block 单元测试。
- 新增 Batch49 静态合同。
