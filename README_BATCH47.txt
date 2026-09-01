RC13 Batch47 - UI test sync + splitter warning cleanup

- 更新统一抓包 UI 测试：接口控件使用 comboCaptureInterface（可编辑 QComboBox），抓包模式数量为 4（WAN/主站/终端/自定义）。
- DetachablePanelManager 创建包装容器时先保持无父对象，再交给 QSplitter/QBoxLayout 接管，避免 QSplitter::replaceWidget 把新包装器误判为现有 sibling 并输出重复 warning。
- 不修改 WAN、抓包、诊断业务逻辑。
- Windows 动态回归目标：61 tests。
