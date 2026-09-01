RC13 Batch46 - Windows 编译回归 / 快捷命令同名修复

本批次只修复 Batch45 在 Windows + VS2022 + Qt 6.8.3 动态编译/回归中暴露的问题，不改变抓包/WAN/串口诊断设计：

1. 修复 MainWindow.cpp 残留 ui->editIface 导致的 C2039 编译失败：
   - Batch45 的 MainWindow.ui 已经包含 comboCaptureInterface 和 btnRefreshCaptureInterfaces；
   - MainWindow.cpp 现在直接复用 UI 中这两个控件，不再动态创建第二套接口控件；
   - 响应式布局仍通过 captureInterfacePanel 将“接口选择 + 刷新接口”作为一组移动；
   - 禁止再次引用已经删除的 editIface。
2. 修复快捷命令同名遮蔽：
   - 用户保存的自定义快捷命令优先加载；
   - 内置快捷命令随后追加，因此用户自定义“查看进程 / ps”等同名项仍可被正常选中；
   - 内置“查看进程 / ps”和“重启路由器 / reboot”继续保留。
3. 新增 Batch46 静态合同，锁定 UI 控件迁移和自定义命令优先级，避免再次出现 UIC 成员不一致或同名命令遮蔽。

Windows + VS2022 + Qt 6.8.3 最终动态回归应为 60 tests。
