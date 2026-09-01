#pragma once

#include <QString>
#include <QList>

struct AtRegistrationInfo {
    bool valid = false;
    int mode = -1;          // <n>, when present
    int status = -1;        // <stat>
    QString areaCode;       // LAC/TAC
    QString cellId;
    int accessTechnology = -1;
    int rejectType = -1;
    int rejectCause = -1;
    QString raw;
    QList<bool> fieldQuoted; // 对应CSV字段在原始AT响应中是否被双引号包围

    bool registered() const { return status == 1 || status == 5 || status == 9 || status == 10; }
    bool roaming() const { return status == 5 || status == 10; }
    bool limitedRegistration() const { return status == 6 || status == 7 || status == 8; }
};

struct AtRegistrationSelection {
    QString source;
    AtRegistrationInfo info;
    bool valid() const { return info.valid; }
};

struct AtOperatorInfo {
    bool valid = false;
    int mode = -1;
    int format = -1;
    QString operatorName;
    int accessTechnology = -1;
    QString raw;
};

class AtStatusParser {
public:
    static AtRegistrationInfo parseRegistration(const QString& value);
    static QString registrationStatusText(int status);
    static QString accessTechnologyText(int act);
    static QString cmeErrorText(int code);
    static QString rejectCauseText(int code);
    static AtOperatorInfo parseOperator(const QString& value);
    static AtRegistrationSelection preferredRegistration(const QString& c5greg,const QString& cereg,const QString& cgreg,const QString& creg,int operatorAccessTechnology=-1);
};
