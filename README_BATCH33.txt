Batch33 - 可伸缩 / 可悬浮工作区

1. 实时抓包：报文+统计、包详情两块支持随窗口自动伸缩、分割条调整、拖出悬浮。
2. 现场诊断层级列表、Ping实时结果、网口详情、实时运行日志支持拖出悬浮。
3. 多抓包 CaptureSessionWidget 改为纵向/横向 QSplitter，报文、统计、详情均可独立悬浮。
4. 命令/快捷指令窗口使用可调 QSplitter；快捷命令列表和命令输出可独立悬浮；Ping/模块日志输出也可悬浮。
5. 清理 tableInterfaces、Ping 输出和多抓包统计/详情的固定最大高度。
6. 主窗口 splitter 比例和浮窗 geometry 通过 QSettings 保存；浮窗关闭后自动回原位。
7. 浮窗不是数据副本，移动的是原 QWidget，因此实时数据、选择状态和抓包状态保持一致。

验证：tests/batch33_resizable_floating_workspace_contract.cmake
Windows + Qt 环境请重新运行 package_onefile_release_lite.bat 做真实编译/打包验证。
