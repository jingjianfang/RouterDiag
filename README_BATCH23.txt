FourFaith RouterDiag v1.2 RC12 - Batch23

本批次变更：
1. 用户界面与诊断报告统一使用“模组”名称，不再显示“蜂窝模组”。
2. 路由器控制 Telnet 登录成功后，设备自动检测会同时尝试识别模组 AT 控制口。
3. 优先从 /tmp/.systemlog 的 CONTROL DEVICES 证据选择控制口，再补充扫描 /dev/ttyUSB*、/dev/ttyACM*。
4. 对候选端口先发送 ATI，收到 OK 后再查询 AT+CGMI、AT+CGMM、AT+CGMR。
5. 路由器存在 at_test 时优先通过 at_test 发送；at_test 不存在或未得到 OK 时，回退为直接读写设备节点。
6. 直接读写使用临时后台 reader，并在短暂等待后 kill/wait 回收，不遗留长期 cat 进程。
7. 模组卡片显示识别到的型号；Tooltip 展示厂商、型号、固件和 AT 口。

说明：
- /dev/ttyUSB* 仍仅作为模组 AT/control device 使用，不作为外部终端串口。
- 当前 Linux 构建环境缺少 Qt5/Qt6 开发包，因此本地无法执行 QtTest/完整编译；CMake 契约测试可独立验证。
