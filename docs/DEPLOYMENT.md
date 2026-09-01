# 四信路由器通信诊断工具 v1.2 单文件发布

## 给现场人员的文件

正常发布时只需要分发：

```text
FourFaith_RouterDiag_v1.2.exe
```

目标电脑**无需安装 Qt**，也**无需安装 Visual Studio**。程序运行所需的 Qt 6 和 MSVC x64 运行库都封装在单文件 EXE 内。

## 打包方法

在 Windows 10/11、Visual Studio 2022 C++ 和 Qt 6.8.3 `msvc2022_64` 已安装的开发机上，从工程根目录执行：

```cmd
package_onefile_release.bat
```

Qt 不在默认目录时：

```cmd
package_onefile_release.bat D:\Qt\6.8.3\msvc2022_64
```

脚本执行：Release x64 编译 → `windeployqt` 部署 Qt → 复制 MSVC 运行库 → 校验 `platforms\qwindows.dll` → 压缩运行环境 → Windows IExpress 封装成单文件 → 生成 SHA256。

最终输出：

```text
dist\FourFaith_RouterDiag_v1.2.exe
dist\FourFaith_RouterDiag_v1.2_SHA256.txt
```

## 单文件 EXE 如何运行

`FourFaith_RouterDiag_v1.2.exe` 是自解压启动器。双击后会把私有 Qt/MSVC 运行环境释放到当前用户的**临时目录**，启动真正的 `WanDiagTool.exe`；关闭程序后启动器会尝试删除该临时目录。

因此它是“对用户只有一个 EXE”的发布方式，并不是静态链接 Qt 的纯单二进制文件。

## Windows 安全提示

当前工程没有配置商业代码签名证书，因此其他电脑第一次运行时 Windows Defender **SmartScreen** 可能显示“Windows 已保护你的电脑”。这是未签名自解压 EXE 常见的信誉提示，不代表程序一定有恶意行为。

正式大规模分发时建议购买并配置 Authenticode 代码签名证书，然后对最终 `FourFaith_RouterDiag_v1.2.exe` 签名。

企业安全策略如果禁止 IExpress/自解压程序，可以改用普通绿色 ZIP 发布；程序本体和依赖完全相同。

## 系统要求

- Windows 10/11 x64
- 能访问待诊断路由设备的网络
- 路由设备提供当前工具所需的 Telnet/tcpdump 能力
- 文本抓包转 PCAP 功能不要求目标电脑安装 Wireshark

## 发布前检查

建议在一台**没有安装 Qt、没有安装 Visual Studio**的干净 Windows 10/11 x64 电脑或虚拟机中进行一次最终验收：

1. 仅复制 `FourFaith_RouterDiag_v1.2.exe`；
2. 双击启动；
3. 打开四个主界面 Tab；
4. 导入一个 PCAP；
5. 执行一次 tcpdump 文本转 PCAP；
6. 关闭程序后确认没有持续运行的 `WanDiagTool.exe` 进程。

这一步是验证“别人电脑可直接使用”的最终标准。

## 精简现场版（推荐给现场人员）

需要减小单文件体积时，使用：

```cmd
package_onefile_release_lite.bat
```

Qt 不在默认目录时：

```cmd
package_onefile_release_lite.bat D:\Qt\6.8.3\msvc2022_64
```

精简版仍输出：

```text
dist\FourFaith_RouterDiag_v1.2.exe
```

它先使用 `windeployqt` 得到正确的 Qt 运行环境，再删除当前程序未使用的可选组件，包括重复的 `vc_redist.x64.exe`、软件 OpenGL、随包 D3D/DX shader 编译器、SVG、额外图片格式、触摸、TLS 和网络信息插件。MSVC CRT DLL 仍以 app-local 方式保留，`Qt6Core/Gui/Network/SerialPort/Widgets`、`platforms\qwindows.dll` 以及 Windows 风格插件仍保留。

精简版面向 **Windows 10/11 x64**。当前程序通过普通 Telnet/TCP 工作，不依赖 Qt TLS；如果以后新增 HTTPS/TLS、SVG 图标、外部 JPEG/GIF 加载、OpenGL 或相关 Qt 功能，需要重新评估精简清单，不能直接沿用旧脚本。

打包完成时脚本会显示三项大小：精简后的运行目录、`payload.zip`、最终单文件 EXE。给现场人员只需要发送最终的 `FourFaith_RouterDiag_v1.2.exe`；SHA256 文件可由开发/发布人员自行留档。
