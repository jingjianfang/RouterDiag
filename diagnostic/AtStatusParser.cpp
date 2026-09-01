#include "AtStatusParser.h"

#include <QStringList>

namespace {
struct CsvField { QString text; bool quoted=false; };

QList<CsvField> splitCsvFields(const QString& input)
{
    QString value=input.trimmed();
    const int colon=value.indexOf(QLatin1Char(':'));
    if(colon>=0)value=value.mid(colon+1).trimmed();
    QList<CsvField> out;QString current;bool quoted=false;bool fieldQuoted=false;
    for(QChar ch:value){
        if(ch==QLatin1Char('"')){quoted=!quoted;fieldQuoted=true;continue;}
        if(ch==QLatin1Char(',') && !quoted){out.append({current.trimmed(),fieldQuoted});current.clear();fieldQuoted=false;}
        else current+=ch;
    }
    out.append({current.trimmed(),fieldQuoted});
    return out;
}

int asInt(const QString& value,bool* okOut=nullptr)
{
    bool ok=false;const int n=value.trimmed().toInt(&ok);if(okOut)*okOut=ok;return ok?n:-1;
}

bool statCandidate(const CsvField& value)
{
    bool ok=false;const int n=asInt(value.text,&ok);return ok&&!value.quoted&&n>=0&&n<=10;
}
}

AtRegistrationInfo AtStatusParser::parseRegistration(const QString& input)
{
    AtRegistrationInfo r;r.raw=input.trimmed();
    const QList<CsvField> p=splitCsvFields(input);
    if(p.isEmpty())return r;
    for(const CsvField& f:p)r.fieldQuoted.append(f.quoted);

    int statIndex=0;
    // Query response: <n>,<stat>[,...]. Unsolicited response: <stat>,"<tac>","<ci>"...
    // A quoted TAC such as "0001" must never be mistaken for <stat>.
    if(p.size()>=2 && statCandidate(p.at(1))){
        bool ok=false;const int n=asInt(p.at(0).text,&ok);
        if(ok && n>=0 && n<=5){r.mode=n;statIndex=1;}
    }
    bool ok=false;r.status=asInt(p.value(statIndex).text,&ok);if(!ok)return r;
    r.valid=(r.status>=0&&r.status<=10);if(!r.valid)return r;
    const int base=statIndex+1;
    if(p.size()>base)r.areaCode=p.at(base).text;
    if(p.size()>base+1)r.cellId=p.at(base+1).text;
    if(p.size()>base+2){bool actOk=false;r.accessTechnology=asInt(p.at(base+2).text,&actOk);if(!actOk)r.accessTechnology=-1;}
    if(p.size()>base+3){bool causeTypeOk=false;r.rejectType=asInt(p.at(base+3).text,&causeTypeOk);if(!causeTypeOk)r.rejectType=-1;}
    if(p.size()>base+4){bool rejectOk=false;r.rejectCause=asInt(p.at(base+4).text,&rejectOk);if(!rejectOk)r.rejectCause=-1;}
    return r;
}

QString AtStatusParser::registrationStatusText(int status)
{
    switch(status){
    case 0:return QStringLiteral("未注册，未搜索");
    case 1:return QStringLiteral("已注册");
    case 2:return QStringLiteral("正在搜索网络");
    case 3:return QStringLiteral("注册被拒绝");
    case 4:return QStringLiteral("状态未知");
    case 5:return QStringLiteral("已注册(漫游)");
    case 6:return QStringLiteral("仅SMS注册(本地)，数据业务受限");
    case 7:return QStringLiteral("仅SMS注册(漫游)，数据业务受限");
    case 8:return QStringLiteral("仅紧急业务");
    case 9:return QStringLiteral("已注册(CSFB非首选，本地)");
    case 10:return QStringLiteral("已注册(CSFB非首选，漫游)");
    default:return QStringLiteral("未知");
    }
}

QString AtStatusParser::accessTechnologyText(int act)
{
    switch(act){
    case 0:return QStringLiteral("GSM");
    case 1:return QStringLiteral("GSM Compact");
    case 2:return QStringLiteral("UTRAN/3G");
    case 3:return QStringLiteral("GSM/EGPRS");
    case 4:return QStringLiteral("HSDPA");
    case 5:return QStringLiteral("HSUPA");
    case 6:return QStringLiteral("HSPA");
    case 7:return QStringLiteral("LTE");
    case 8:return QStringLiteral("EC-GSM-IoT");
    case 9:return QStringLiteral("NB-IoT");
    case 10:return QStringLiteral("LTE-M");
    case 11:return QStringLiteral("NR/5G");
    case 13:return QStringLiteral("NR/5G");
    default:return act>=0?QStringLiteral("AcT=%1").arg(act):QString();
    }
}

QString AtStatusParser::cmeErrorText(int code)
{
    switch(code){
    case 10:return QStringLiteral("SIM未插入");
    case 11:return QStringLiteral("需要SIM PIN");
    case 12:return QStringLiteral("需要SIM PUK");
    case 13:return QStringLiteral("SIM故障");
    case 14:return QStringLiteral("SIM忙");
    case 15:return QStringLiteral("SIM错误");
    case 17:return QStringLiteral("需要SIM PIN2");
    case 18:return QStringLiteral("需要SIM PUK2");
    case 30:return QStringLiteral("无网络服务");
    case 31:return QStringLiteral("网络超时");
    case 32:return QStringLiteral("仅允许紧急呼叫");
    default:return code>=0?QStringLiteral("CME ERROR %1").arg(code):QStringLiteral("CME ERROR");
    }
}

QString AtStatusParser::rejectCauseText(int code)
{
    // Common 3GPP MM/EMM/5GMM registration reject causes. Vendors may expose
    // additional values; keep unknown codes visible instead of guessing.
    switch(code){
    case 2:return QStringLiteral("IMSI在HLR/HSS中未知");
    case 3:return QStringLiteral("非法移动台/UE");
    case 6:return QStringLiteral("非法设备ME");
    case 7:return QStringLiteral("分组业务/EPS服务不允许");
    case 8:return QStringLiteral("分组业务和非分组业务均不允许");
    case 9:return QStringLiteral("UE身份无法从网络推导");
    case 10:return QStringLiteral("隐式去附着");
    case 11:return QStringLiteral("当前PLMN不允许");
    case 12:return QStringLiteral("当前跟踪区/位置区不允许");
    case 13:return QStringLiteral("当前跟踪区/位置区不允许漫游");
    case 14:return QStringLiteral("当前位置不允许EPS服务");
    case 15:return QStringLiteral("当前跟踪区/位置区无合适小区");
    case 17:return QStringLiteral("网络故障");
    case 20:return QStringLiteral("MAC失败");
    case 21:return QStringLiteral("同步失败");
    case 22:return QStringLiteral("拥塞");
    case 23:return QStringLiteral("UE安全能力不匹配");
    case 25:return QStringLiteral("CS域暂不可用");
    case 26:return QStringLiteral("服务选项未订阅");
    case 27:return QStringLiteral("服务选项暂时不可用");
    case 35:return QStringLiteral("请求服务不允许");
    case 39:return QStringLiteral("CS域暂不可用");
    case 40:return QStringLiteral("无EPS承载上下文激活");
    case 95:return QStringLiteral("语义错误的消息");
    case 96:return QStringLiteral("无效的强制信息");
    case 97:return QStringLiteral("消息类型不存在或未实现");
    case 98:return QStringLiteral("消息与协议状态不兼容");
    case 99:return QStringLiteral("信息元素不存在或未实现");
    case 100:return QStringLiteral("条件信息元素错误");
    case 101:return QStringLiteral("消息与协议状态不兼容");
    case 111:return QStringLiteral("协议错误（未指定）");
    default:return code>=0?QStringLiteral("拒绝原因码 %1").arg(code):QString();
    }
}

AtOperatorInfo AtStatusParser::parseOperator(const QString& input)
{
    AtOperatorInfo r;r.raw=input.trimmed();
    const QList<CsvField> p=splitCsvFields(input);
    if(p.isEmpty())return r;
    bool ok=false;r.mode=asInt(p.value(0).text,&ok);if(!ok)return r;
    if(p.size()>1){bool f=false;r.format=asInt(p.value(1).text,&f);if(!f)r.format=-1;}
    if(p.size()>2)r.operatorName=p.value(2).text;
    if(p.size()>3){bool a=false;r.accessTechnology=asInt(p.value(3).text,&a);if(!a)r.accessTechnology=-1;}
    r.valid=true;return r;
}

AtRegistrationSelection AtStatusParser::preferredRegistration(const QString& c5greg,const QString& cereg,const QString& cgreg,const QString& creg,int operatorAccessTechnology)
{
    const QList<QPair<QString,QString>> all={
        {QStringLiteral("C5GREG"),c5greg},{QStringLiteral("CEREG"),cereg},
        {QStringLiteral("CGREG"),cgreg},{QStringLiteral("CREG"),creg}};
    auto pick=[&all](const QStringList& names)->AtRegistrationSelection{
        for(const QString& name:names)for(const auto& item:all)if(item.first==name){
            const AtRegistrationInfo info=AtStatusParser::parseRegistration(item.second);
            if(info.valid)return {item.first,info};
        }
        return {};
    };
    // RAT-aware domain selection: 5G -> C5GREG, LTE/NB/LTE-M -> CEREG, legacy -> CGREG/CREG.
    if(operatorAccessTechnology==11||operatorAccessTechnology==13){auto r=pick({QStringLiteral("C5GREG"),QStringLiteral("CEREG")});if(r.valid())return r;}
    if(operatorAccessTechnology==7||operatorAccessTechnology==9||operatorAccessTechnology==10){auto r=pick({QStringLiteral("CEREG"),QStringLiteral("C5GREG")});if(r.valid())return r;}
    if(operatorAccessTechnology>=0&&operatorAccessTechnology<=8){auto r=pick({QStringLiteral("CGREG"),QStringLiteral("CREG"),QStringLiteral("CEREG")});if(r.valid())return r;}
    // COPS may be unavailable. Infer from an available registration AcT before using a conservative fallback order.
    for(const auto& item:all){const AtRegistrationInfo info=AtStatusParser::parseRegistration(item.second);if(!info.valid)continue;
        if(info.accessTechnology==11||info.accessTechnology==13){auto r=pick({QStringLiteral("C5GREG"),QStringLiteral("CEREG")});if(r.valid())return r;}
        if(info.accessTechnology==7||info.accessTechnology==9||info.accessTechnology==10){auto r=pick({QStringLiteral("CEREG"),QStringLiteral("C5GREG")});if(r.valid())return r;}
    }
    return pick({QStringLiteral("C5GREG"),QStringLiteral("CEREG"),QStringLiteral("CGREG"),QStringLiteral("CREG")});
}

