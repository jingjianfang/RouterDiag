# Batch58 FieldLite

本版本重点：减少 GroupBox/Frame 边框，使用留白、字体层级和状态颜色降低现场使用的视觉负担。原有 objectName 和主要诊断流程保持不变。

## 编译
双击 `build_release.bat`，或在 VS2022 x64 Native Tools 命令行执行：

```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

EXE：`build\Release\WanDiagTool.exe`

Qt 运行库部署：
`windeployqt build\Release\WanDiagTool.exe`

说明：当前环境未安装 Qt/Visual Studio，无法在此处执行实际 Qt 编译；源码已针对 Qt5/Qt6 的现有工程结构保留。
