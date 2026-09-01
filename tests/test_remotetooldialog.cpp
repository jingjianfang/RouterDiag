#include <QtTest>
#include <QComboBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QLabel>
#include <QTextDocument>
#include <QSettings>
#include <QCoreApplication>
#include "ui/RemoteToolDialog.h"

class TestRemoteToolDialog : public QObject {
    Q_OBJECT
private slots:
    void initTestCase(){
        QCoreApplication::setApplicationName(QStringLiteral("test_remotetooldialog"));
        QSettings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagToolTests")).clear();
    }

    void cleanupTestCase(){
        QSettings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagToolTests")).clear();
    }

    void pingDialogDefaultsToTenPackets(){
        RemoteConnectionParams p{QStringLiteral("192.168.1.1"),23,QStringLiteral("admin"),QStringLiteral("admin")};
        RemoteToolDialog d(RemoteToolDialog::Mode::Ping,p,QStringLiteral("223.5.5.5"));
        auto* target=d.findChild<QLineEdit*>(QStringLiteral("editRemotePingTarget"));
        auto* count=d.findChild<QSpinBox*>(QStringLiteral("spinRemotePingCount"));
        QVERIFY(target);QVERIFY(count);
        QCOMPARE(target->text(),QStringLiteral("223.5.5.5"));
        QCOMPARE(count->value(),10);
    }

    void moduleLogDefaultsToAutoSaveAndFolderActions(){
        QSettings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagToolTests")).remove(QStringLiteral("moduleLog/autoSave"));
        RemoteConnectionParams p{QStringLiteral("192.168.1.1"),23,QStringLiteral("admin"),QStringLiteral("admin")};
        RemoteToolDialog d(RemoteToolDialog::Mode::ModuleLog,p);
        auto* autoSave=d.findChild<QCheckBox*>(QStringLiteral("checkModuleLogAutoSave"));
        auto* openFolder=d.findChild<QPushButton*>(QStringLiteral("btnOpenModuleLogFolder"));
        auto* saveAs=d.findChild<QPushButton*>(QStringLiteral("btnSaveModuleLogAs"));
        auto* output=d.findChild<QPlainTextEdit*>(QStringLiteral("txtRemoteOutput"));
        auto* summary=d.findChild<QLabel*>(QStringLiteral("labelModuleLiveSummary"));
        auto* runtime=d.findChild<QLabel*>(QStringLiteral("labelModuleLogRuntime"));
        QVERIFY(autoSave);QVERIFY(openFolder);QVERIFY(saveAs);QVERIFY(output);QVERIFY(summary);QVERIFY(runtime);
        QVERIFY(autoSave->isChecked());
        QCOMPARE(output->document()->maximumBlockCount(),5000);
        QVERIFY(summary->text().contains(QStringLiteral("RSRP")));
        QVERIFY(summary->text().contains(QStringLiteral("SINR")));
        QVERIFY(runtime->text().contains(QStringLiteral("tail /tmp/.systemlog -f")));
        QVERIFY(runtime->text().contains(QString::fromUtf8("已接收")));
    }

    void commandDialogSupportsSavedQuickCommands(){
        RemoteConnectionParams p{QStringLiteral("192.168.1.1"),23,QStringLiteral("admin"),QStringLiteral("admin")};
        RemoteToolDialog d(RemoteToolDialog::Mode::Command,p);
        QVERIFY(d.findChild<QComboBox*>(QStringLiteral("comboRemoteCommand")));
        auto* table=d.findChild<QTableWidget*>(QStringLiteral("tableQuickCommands"));
        QVERIFY(table);
        QCOMPARE(table->columnCount(),4);
        QCOMPARE(table->horizontalHeaderItem(0)->text(),QString::fromUtf8("分类"));
        QCOMPARE(table->horizontalHeaderItem(3)->text(),QString::fromUtf8("备注"));
        QVERIFY(d.findChild<QComboBox*>(QStringLiteral("comboQuickCommandCategoryFilter")));
        QVERIFY(d.findChild<QLineEdit*>(QStringLiteral("editQuickCommandSearch")));
        QVERIFY(d.findChild<QLineEdit*>(QStringLiteral("editRemoteCommandText")));
        QVERIFY(d.findChild<QPushButton*>(QStringLiteral("btnCommandAdd")));
        QVERIFY(d.findChild<QPushButton*>(QStringLiteral("btnCommandEdit")));
        QVERIFY(d.findChild<QPushButton*>(QStringLiteral("btnCommandDelete")));
        QVERIFY(RemoteToolDialog::commandNeedsConfirmation(QStringLiteral("nvram set foo=bar")));
        QVERIFY(RemoteToolDialog::commandNeedsConfirmation(QStringLiteral("nvram commit")));
        QVERIFY(RemoteToolDialog::commandNeedsConfirmation(QStringLiteral("reboot")));
        QVERIFY(RemoteToolDialog::commandNeedsConfirmation(QStringLiteral("rm -rf /tmp/test")));
        QVERIFY(RemoteToolDialog::commandNeedsConfirmation(QStringLiteral("kill 1234")));
        QVERIFY(!RemoteToolDialog::commandNeedsConfirmation(QStringLiteral("ifconfig")));
    }

    void commandDialogLoadsPersistedCustomCommand(){
        QSettings settings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagToolTests"));
        settings.remove(QStringLiteral("remoteCommands/custom"));
        settings.beginWriteArray(QStringLiteral("remoteCommands/custom"));
        settings.setArrayIndex(0);
        settings.setValue(QStringLiteral("name"),QString::fromUtf8("查看进程"));
        settings.setValue(QStringLiteral("command"),QStringLiteral("ps"));
        settings.setValue(QStringLiteral("note"),QString::fromUtf8("查看当前进程"));
        settings.endArray();
        settings.sync();
        RemoteConnectionParams p{QStringLiteral("192.168.1.1"),23,QStringLiteral("admin"),QStringLiteral("admin")};
        RemoteToolDialog d(RemoteToolDialog::Mode::Command,p);
        auto* combo=d.findChild<QComboBox*>(QStringLiteral("comboRemoteCommand"));
        QVERIFY(combo);
        const int index=combo->findText(QString::fromUtf8("查看进程"));
        QVERIFY(index>=0);
        QCOMPARE(combo->itemData(index,Qt::UserRole).toString(),QStringLiteral("ps"));
        auto* table=d.findChild<QTableWidget*>(QStringLiteral("tableQuickCommands"));
        auto* edit=d.findChild<QLineEdit*>(QStringLiteral("editRemoteCommandText"));
        QVERIFY(table);QVERIFY(edit);
        QCOMPARE(table->item(index,0)->text(),QString::fromUtf8("自定义"));
        QCOMPARE(table->item(index,2)->text(),QStringLiteral("ps"));
        QCOMPARE(table->item(index,3)->text(),QString::fromUtf8("查看当前进程"));
        QVERIFY(QMetaObject::invokeMethod(table,"cellClicked",Qt::DirectConnection,Q_ARG(int,index),Q_ARG(int,0)));
        QCOMPARE(edit->text(),QStringLiteral("ps"));
        settings.remove(QStringLiteral("remoteCommands/custom"));
    }

    void commandDialogHasFieldCommands(){
        RemoteConnectionParams p{QStringLiteral("192.168.1.1"),23,QStringLiteral("admin"),QStringLiteral("admin")};
        RemoteToolDialog d(RemoteToolDialog::Mode::Command,p);
        auto* table=d.findChild<QTableWidget*>(QStringLiteral("tableQuickCommands"));
        QVERIFY(table);
        bool foundIfconfig=false,foundNetstat=false,foundUptime=false,foundPs=false,foundReboot=false,foundModuleSummary=false;
        for(int row=0;row<table->rowCount();++row){
            const QString category=table->item(row,0)?table->item(row,0)->text():QString();
            const QString name=table->item(row,1)?table->item(row,1)->text():QString();
            const QString command=table->item(row,2)?table->item(row,2)->text():QString();
            if(command==QStringLiteral("ifconfig"))foundIfconfig=(name==QString::fromUtf8("查看网口") && category==QString::fromUtf8("只读检查"));
            if(command==QStringLiteral("netstat -an"))foundNetstat=(category==QStringLiteral("只读检查"));
            if(command==QStringLiteral("uptime"))foundUptime=(category==QString::fromUtf8("只读检查"));
            if(command==QStringLiteral("ps"))foundPs=(name==QString::fromUtf8("查看进程") && category==QString::fromUtf8("只读检查"));
            if(command==QStringLiteral("reboot"))foundReboot=(name==QString::fromUtf8("重启路由器") && category==QString::fromUtf8("维护操作"));
            if(name==QString::fromUtf8("查看模组和信号"))foundModuleSummary=(category==QString::fromUtf8("只读检查") && command.contains(QStringLiteral("comm_rsrp")));
        }
        QVERIFY(foundIfconfig);QVERIFY(foundNetstat);QVERIFY(foundUptime);QVERIFY(foundPs);QVERIFY(foundReboot);QVERIFY(foundModuleSummary);
    }
};

QTEST_MAIN(TestRemoteToolDialog)
#include "test_remotetooldialog.moc"
