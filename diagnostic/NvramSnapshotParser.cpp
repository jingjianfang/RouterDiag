#include "NvramSnapshotParser.h"

#include <QRegularExpression>
#include <QStringList>

namespace {
const QByteArray kFourFaithMagic("FOUR-FAITH:");

QString decodeValue(const QByteArray& bytes)
{
    QString value=QString::fromUtf8(bytes);
    if(value.contains(QChar(0xfffd))) value=QString::fromLocal8Bit(bytes);
    return value;
}

bool plausibleKey(const QString& key)
{
    static const QRegularExpression re(QStringLiteral(R"(^[A-Za-z0-9_.-]{1,255}$)"));
    return re.match(key).hasMatch();
}

bool hasSnapshotAnchor(const QMap<QString,QString>& values)
{
    static const QStringList anchors={
        QStringLiteral("nvram_ver"),QStringLiteral("wan_proto"),QStringLiteral("wan_proto_type"),
        QStringLiteral("router_name"),QStringLiteral("lan_ipaddr"),QStringLiteral("comm_module_status"),
        QStringLiteral("modulename"),QStringLiteral("current_module_real_name"),QStringLiteral("dts_en")
    };
    for(const QString& key:anchors) if(values.contains(key)) return true;
    return false;
}

NvramSnapshot parseFourFaithBinary(const QByteArray& bytes)
{
    NvramSnapshot snapshot;
    snapshot.format=NvramSnapshotFormat::FourFaithBinary;
    if(!bytes.startsWith(kFourFaithMagic)){
        snapshot.error=QStringLiteral("不是 FOUR-FAITH 配置文件");
        return snapshot;
    }
    int pos=kFourFaithMagic.size();
    if(pos>=bytes.size()){
        snapshot.error=QStringLiteral("FOUR-FAITH 配置文件缺少格式版本");
        return snapshot;
    }
    snapshot.binaryVersion=quint8(bytes.at(pos++));

    while(pos<bytes.size()){
        if(pos+1>bytes.size()){
            snapshot.error=QStringLiteral("配置记录缺少键长度");
            return snapshot;
        }
        const int keyLength=quint8(bytes.at(pos++));
        if(keyLength<=0){
            snapshot.error=QStringLiteral("配置记录包含空键");
            return snapshot;
        }
        if(pos+keyLength+2>bytes.size()){
            snapshot.error=QStringLiteral("配置记录键或值长度字段被截断（记录 %1）").arg(snapshot.recordCount+1);
            return snapshot;
        }
        const QByteArray keyBytes=bytes.mid(pos,keyLength);
        pos+=keyLength;
        const quint16 valueLength=quint8(bytes.at(pos)) | (quint16(quint8(bytes.at(pos+1)))<<8);
        pos+=2;
        if(pos+int(valueLength)>bytes.size()){
            snapshot.error=QStringLiteral("配置记录值被截断（记录 %1）").arg(snapshot.recordCount+1);
            return snapshot;
        }
        const QString key=QString::fromLatin1(keyBytes);
        if(!plausibleKey(key)){
            snapshot.error=QStringLiteral("配置记录键格式异常（记录 %1）").arg(snapshot.recordCount+1);
            return snapshot;
        }
        const QByteArray valueBytes=bytes.mid(pos,valueLength);
        pos+=valueLength;
        snapshot.values.insert(key,decodeValue(valueBytes));
        ++snapshot.recordCount;
    }

    snapshot.valid=snapshot.recordCount>0;
    if(!snapshot.valid && snapshot.error.isEmpty()) snapshot.error=QStringLiteral("配置文件没有记录");
    return snapshot;
}
}

NvramSnapshot NvramSnapshotParser::parse(const QByteArray& bytes)
{
    if(bytes.startsWith(kFourFaithMagic)) return parseFourFaithBinary(bytes);
    QString text=QString::fromUtf8(bytes);
    if(text.contains(QChar(0xfffd))) text=QString::fromLocal8Bit(bytes);
    return parseText(text);
}

NvramSnapshot NvramSnapshotParser::parseText(const QString& text)
{
    NvramSnapshot snapshot;
    snapshot.format=NvramSnapshotFormat::Text;
    const QStringList lines=text.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(const QString& raw:lines){
        QString line=raw.trimmed();
        if(line.isEmpty() || line.startsWith(QLatin1Char('#'))) continue;
        const int eq=line.indexOf(QLatin1Char('='));
        if(eq<=0) continue;
        const QString key=line.left(eq).trimmed();
        if(!plausibleKey(key)) continue;
        // Shell completion markers and command echoes are not NVRAM records.
        if(key.startsWith(QStringLiteral("__FF_"),Qt::CaseInsensitive) ||
           key.compare(QStringLiteral("__ff_rc"),Qt::CaseInsensitive)==0) continue;
        snapshot.values.insert(key,line.mid(eq+1));
        ++snapshot.recordCount;
    }
    snapshot.valid=snapshot.recordCount>=5 && hasSnapshotAnchor(snapshot.values);
    if(!snapshot.valid) snapshot.error=QStringLiteral("文本不像完整的 nvram show 快照");
    return snapshot;
}

QString NvramSnapshotParser::formatName(NvramSnapshotFormat format)
{
    switch(format){
    case NvramSnapshotFormat::FourFaithBinary:return QStringLiteral("Four-Faith binary");
    case NvramSnapshotFormat::Text:return QStringLiteral("nvram show text");
    default:return QStringLiteral("unknown");
    }
}

bool NvramSnapshotParser::isSensitiveKey(const QString& key)
{
    const QString k=key.trimmed().toLower();
    if(k.isEmpty()) return false;
    static const QStringList tokens={
        QStringLiteral("passwd"),QStringLiteral("password"),QStringLiteral("_psk"),QStringLiteral("passphrase"),
        QStringLiteral("private_key"),QStringLiteral("authorized_keys"),QStringLiteral("tlsauth"),
        QStringLiteral("username"),QStringLiteral("_user"),QStringLiteral("imei"),QStringLiteral("imsi"),
        QStringLiteral("iccid"),QStringLiteral("termsn"),QStringLiteral("dtuid"),QStringLiteral("deviceid"),
        QStringLiteral("devid"),QStringLiteral("http_client_mac"),QStringLiteral("hwaddr")
    };
    for(const QString& token:tokens) if(k.contains(token)) return true;
    // Generic *_key fields are credentials/cryptographic material on many firmware branches.
    if(k.endsWith(QStringLiteral("_key")) || k.contains(QStringLiteral("_key="))) return true;
    return false;
}
