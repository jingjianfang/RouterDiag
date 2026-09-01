#include <QApplication>
#include <QIcon>
#include "MainWindow.h"
#include "capture/PcapTypes.h"

int main(int argc,char*argv[])
{
    QApplication app(argc,argv);
    app.setOrganizationName(QStringLiteral("FourFaith"));
    app.setApplicationName(QStringLiteral("WanDiagTool"));
    app.setApplicationDisplayName(QStringLiteral("四信路由器通信诊断工具"));
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/app_icon_1024.png")));
    qRegisterMetaType<PcapGlobalHeaderInfo>();
    qRegisterMetaType<PcapRecord>();
    qRegisterMetaType<ParsedPacket>();
    qRegisterMetaType<CaptureStats>();
    MainWindow w;
    w.setWindowIcon(app.windowIcon());
    w.show();
    return app.exec();
}
