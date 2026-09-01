#include "DetachablePanelManager.h"

#include <QApplication>
#include <QBoxLayout>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QEvent>
#include <QFrame>
#include <QLabel>
#include <QLayoutItem>
#include <QMouseEvent>
#include <QPushButton>
#include <QSettings>
#include <QSizePolicy>
#include <QSplitter>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>


namespace {
QString workspaceSettingsApplicationName()
{
    const QString appName=QCoreApplication::applicationName();
    return appName.startsWith(QStringLiteral("test_"),Qt::CaseInsensitive)
        ?QStringLiteral("WanDiagToolTests"):QStringLiteral("WanDiagTool");
}
}

DetachablePanelManager::DetachablePanelManager(QWidget* panel,const QString& title,const QString& settingsKey,QObject* parent)
    :QObject(parent),m_panel(panel),m_originalParent(panel?panel->parentWidget():nullptr),m_title(title),m_settingsKey(settingsKey)
{
    if(!m_panel || !m_originalParent)return;
    connect(m_panel,&QObject::destroyed,this,[this]{m_panel=nullptr;});
    connect(m_originalParent,&QObject::destroyed,this,[this]{m_originalParent=nullptr;m_splitter=nullptr;m_boxLayout=nullptr;});
    m_desiredVisible=!m_panel->isHidden();
    buildWrapper();
    if(m_wrapper)connect(m_wrapper,&QObject::destroyed,this,[this]{m_wrapper=nullptr;m_header=nullptr;m_titleLabel=nullptr;m_hintLabel=nullptr;m_floatButton=nullptr;m_headerLayout=nullptr;});
    restoreFloatingState();
}

DetachablePanelManager::~DetachablePanelManager()
{
    if(m_detached && m_wrapper && m_originalParent)reattachPanelInternal(false);
}

void DetachablePanelManager::buildWrapper()
{
    if(!m_panel || !m_originalParent)return;
    m_splitter=qobject_cast<QSplitter*>(m_originalParent);
    if(m_splitter)m_originalIndex=m_splitter->indexOf(m_panel);
    else{
        m_boxLayout=qobject_cast<QBoxLayout*>(m_originalParent->layout());
        if(m_boxLayout)m_originalIndex=m_boxLayout->indexOf(m_panel);
    }
    if(m_originalIndex<0 || (!m_splitter && !m_boxLayout))return;

    m_wrapper=new QFrame(nullptr);
    m_wrapper->setObjectName(QStringLiteral("detachablePanelContainer"));
    m_wrapper->setFrameShape(QFrame::NoFrame);
    m_wrapper->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    m_wrapper->setStyleSheet(QStringLiteral(
        "QFrame#detachablePanelHeader{background:#eef4f8;border:1px solid #d6e1ea;border-radius:5px;}"
        "QLabel#detachablePanelTitle{font-weight:600;color:#35536d;}"
        "QLabel#detachablePanelHint{color:#7b8d9d;font-size:9pt;}"
        "QPushButton#btnFloatPanel{min-height:20px;padding:0;background:transparent;border:1px solid #c4d2dd;border-radius:4px;color:#24679b;}"
        "QPushButton#btnFloatPanel:hover{background:#dfeaf3;}"));

    if(m_splitter)m_splitter->replaceWidget(m_originalIndex,m_wrapper);
    else delete m_boxLayout->replaceWidget(m_panel,m_wrapper);

    auto* wrapperLayout=new QVBoxLayout(m_wrapper);
    wrapperLayout->setContentsMargins(0,0,0,0);
    wrapperLayout->setSpacing(4);
    m_header=new QFrame(m_wrapper);
    m_header->setObjectName(QStringLiteral("detachablePanelHeader"));
    m_header->setCursor(Qt::OpenHandCursor);
    m_header->setFixedHeight(27);
    m_headerLayout=new QHBoxLayout(m_header);
    m_headerLayout->setContentsMargins(8,1,4,1);
    m_headerLayout->setSpacing(6);
    m_titleLabel=new QLabel(m_title,m_header);
    m_titleLabel->setObjectName(QStringLiteral("detachablePanelTitle"));
    m_titleLabel->setAttribute(Qt::WA_TransparentForMouseEvents,true);
    m_hintLabel=new QLabel(QStringLiteral("拖出悬浮"),m_header);
    m_hintLabel->setObjectName(QStringLiteral("detachablePanelHint"));
    m_hintLabel->setAttribute(Qt::WA_TransparentForMouseEvents,true);
    m_floatButton=new QPushButton(QStringLiteral("↗"),m_header);
    m_floatButton->setObjectName(QStringLiteral("btnFloatPanel"));
    m_floatButton->setToolTip(QStringLiteral("悬浮 / 返回工作区"));
    m_floatButton->setFixedSize(26,22);
    m_headerLayout->addWidget(m_titleLabel);
    m_headerLayout->addStretch(1);
    m_headerLayout->addWidget(m_hintLabel);
    m_headerLayout->addWidget(m_floatButton);
    wrapperLayout->addWidget(m_header);

    m_panel->setParent(m_wrapper);
    m_panel->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    wrapperLayout->addWidget(m_panel,1);
    m_panel->setVisible(m_desiredVisible);
    m_wrapper->setVisible(m_desiredVisible);

    m_header->installEventFilter(this);
    m_wrapper->installEventFilter(this);
    connect(m_floatButton,&QPushButton::clicked,this,[this]{m_detached?reattachPanel():detachPanel();});
}

QPoint DetachablePanelManager::mouseGlobalPosition(QMouseEvent* event) const
{
#if QT_VERSION >= QT_VERSION_CHECK(6,0,0)
    return event->globalPosition().toPoint();
#else
    return event->globalPos();
#endif
}

bool DetachablePanelManager::eventFilter(QObject* watched,QEvent* event)
{
    if(watched==m_header){
        if(event->type()==QEvent::MouseButtonPress){
            auto* mouse=static_cast<QMouseEvent*>(event);
            if(mouse->button()==Qt::LeftButton){
                m_pressed=true;
                m_pressGlobal=mouseGlobalPosition(mouse);
                if(m_detached && m_wrapper)m_windowOffset=m_pressGlobal-m_wrapper->frameGeometry().topLeft();
                m_header->setCursor(Qt::ClosedHandCursor);
            }
        }else if(event->type()==QEvent::MouseMove && m_pressed){
            auto* mouse=static_cast<QMouseEvent*>(event);
            if(!(mouse->buttons()&Qt::LeftButton))return false;
            const QPoint global=mouseGlobalPosition(mouse);
            if(m_detached){
                m_draggingFloating=true;
                if(m_wrapper)m_wrapper->move(global-m_windowOffset);
                return true;
            }
            if((global-m_pressGlobal).manhattanLength()>=QApplication::startDragDistance()*2){
                detachPanel();
                if(m_wrapper){
                    m_windowOffset=QPoint(qMin(m_wrapper->width()/2,180),13);
                    m_wrapper->move(global-m_windowOffset);
                }
                m_draggingFloating=true;
                return true;
            }
        }else if(event->type()==QEvent::MouseButtonRelease){
            m_pressed=false;m_draggingFloating=false;
            if(m_header)m_header->setCursor(Qt::OpenHandCursor);
        }else if(event->type()==QEvent::MouseButtonDblClick){
            m_detached?reattachPanel():detachPanel();
            return true;
        }
    }
    if(watched==m_wrapper && event->type()==QEvent::Close && m_detached){
        // QCloseEvent is accepted by default. If we reattach synchronously but
        // leave it accepted, QWidget::close() will hide the wrapper again after
        // the event filter returns, making the panel appear to disappear from
        // the workspace. Cancel the top-level close first, then reparent on the
        // next event-loop turn.
        static_cast<QCloseEvent*>(event)->ignore();
        QTimer::singleShot(0,this,[this]{
            if(m_detached)reattachPanel();
        });
        return true;
    }
    return QObject::eventFilter(watched,event);
}

void DetachablePanelManager::detachPanel()
{
    if(m_detached || !m_wrapper || m_originalIndex<0)return;
    if(m_splitter)m_wrapper->setParent(nullptr);
    else{
        m_boxLayout->removeWidget(m_wrapper);
        m_wrapper->setParent(nullptr);
    }
    m_wrapper->setWindowFlag(Qt::Window,true);
    m_wrapper->setWindowTitle(m_title);
    m_wrapper->resize(qMax(760,m_panel?m_panel->width():760),qMax(420,m_panel?m_panel->height()+31:420));
    if(!m_settingsKey.isEmpty()){
        QSettings settings(QStringLiteral("FourFaith"),workspaceSettingsApplicationName());
        const QByteArray geometry=settings.value(QStringLiteral("workspacePanels/%1/geometry").arg(m_settingsKey)).toByteArray();
        if(!geometry.isEmpty())m_wrapper->restoreGeometry(geometry);
        settings.setValue(QStringLiteral("workspacePanels/%1/floating").arg(m_settingsKey),true);
    }
    m_detached=true;
    if(m_floatButton)m_floatButton->setText(QStringLiteral("↙"));
    m_wrapper->setVisible(m_desiredVisible);
    if(m_desiredVisible){m_wrapper->show();m_wrapper->raise();m_wrapper->activateWindow();}
}

void DetachablePanelManager::saveFloatingGeometry()
{
    if(!m_detached || !m_wrapper || m_settingsKey.isEmpty())return;
    QSettings settings(QStringLiteral("FourFaith"),workspaceSettingsApplicationName());
    settings.setValue(QStringLiteral("workspacePanels/%1/geometry").arg(m_settingsKey),m_wrapper->saveGeometry());
}

void DetachablePanelManager::reattachPanelInternal(bool persistState)
{
    if(!m_detached || !m_wrapper)return;
    saveFloatingGeometry();
    m_wrapper->hide();
    m_wrapper->setWindowFlag(Qt::Window,false);
    m_wrapper->setParent(m_originalParent);
    if(m_splitter)m_splitter->insertWidget(qBound(0,m_originalIndex,m_splitter->count()),m_wrapper);
    else if(m_boxLayout)m_boxLayout->insertWidget(qBound(0,m_originalIndex,m_boxLayout->count()),m_wrapper,1);
    m_detached=false;
    if(m_floatButton)m_floatButton->setText(QStringLiteral("↗"));
    if(persistState && !m_settingsKey.isEmpty()){
        QSettings settings(QStringLiteral("FourFaith"),workspaceSettingsApplicationName());
        settings.setValue(QStringLiteral("workspacePanels/%1/floating").arg(m_settingsKey),false);
    }
    m_wrapper->setVisible(m_desiredVisible);
}

void DetachablePanelManager::reattachPanel(){reattachPanelInternal(true);}

void DetachablePanelManager::setPanelVisible(bool visible)
{
    m_desiredVisible=visible;
    if(m_panel)m_panel->setVisible(visible);
    if(m_wrapper)m_wrapper->setVisible(visible);
}

bool DetachablePanelManager::isPanelVisible() const{return m_desiredVisible;}

void DetachablePanelManager::setCompactHeader(bool compact)
{
    if(m_hintLabel)m_hintLabel->setVisible(!compact);
    if(m_header)m_header->setFixedHeight(compact?24:27);
    if(m_floatButton)m_floatButton->setFixedSize(compact?24:26,compact?20:22);
}

void DetachablePanelManager::addHeaderWidget(QWidget* widget)
{
    if(!widget || !m_header || !m_headerLayout)return;
    widget->setParent(m_header);
    const int beforeHint=qMax(1,m_headerLayout->count()-2);
    m_headerLayout->insertWidget(beforeHint,widget,0,Qt::AlignVCenter);
}

QWidget* DetachablePanelManager::container() const{return m_wrapper;}

void DetachablePanelManager::restoreFloatingState()
{
    if(m_settingsKey.isEmpty() || !m_wrapper)return;
    QSettings settings(QStringLiteral("FourFaith"),workspaceSettingsApplicationName());
    if(settings.value(QStringLiteral("workspacePanels/%1/floating").arg(m_settingsKey),false).toBool()){
        QTimer::singleShot(0,this,[this]{detachPanel();});
    }
}
