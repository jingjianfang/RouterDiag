#pragma once
#include <QObject>
#include <QStringList>
#include "DiagnosticTypes.h"
class TelnetClient;
class DiagnosticController : public QObject {
    Q_OBJECT
public:
    explicit DiagnosticController(TelnetClient* client,QObject* parent=nullptr);
    void startDiagnosis();
    void cancel();
    bool isRunning() const{return m_running;}
    static QStringList automaticCommands();
signals:
    void progress(const QString& message);
    void finished(const WanStatus& status,const DiagnosisResult& result,const QString& reportText);
    void failed(const QString& reason);
private:
    void runNext();void finish();QString cleanValue(const QString& output) const;
    TelnetClient* m_client=nullptr;
    QStringList m_commands;
    int m_index=0;
    QString m_combined;
    bool m_cancelled=false;
    bool m_running=false;
    QString m_pendingCommand;
};
