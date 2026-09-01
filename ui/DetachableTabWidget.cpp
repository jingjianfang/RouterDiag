#include "DetachableTabWidget.h"

#include <QApplication>
#include <QCloseEvent>
#include <QEvent>
#include <QMouseEvent>
#include <QTabBar>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

DetachableTabWidget::DetachableTabWidget(QTabWidget* tabs,QObject* parent)
    :QObject(parent),m_tabs(tabs)
{
    if(m_tabs && m_tabs->tabBar())m_tabs->tabBar()->installEventFilter(this);
}

DetachableTabWidget::~DetachableTabWidget()
{
    reattachAll();
}

bool DetachableTabWidget::eventFilter(QObject* watched,QEvent* event)
{
    if(m_tabs && watched==m_tabs->tabBar()){
        auto* bar=m_tabs->tabBar();
        if(event->type()==QEvent::MouseButtonPress){
            auto* mouse=static_cast<QMouseEvent*>(event);
            if(mouse->button()==Qt::LeftButton){
                m_pressPos=mouse->pos();
                m_pressIndex=bar->tabAt(m_pressPos);
                m_dragging=false;
            }
        }else if(event->type()==QEvent::MouseMove && m_pressIndex>=0){
            auto* mouse=static_cast<QMouseEvent*>(event);
            if(mouse->buttons()&Qt::LeftButton && (mouse->pos()-m_pressPos).manhattanLength()>=QApplication::startDragDistance()){
                m_dragging=true;
                // Keep ordinary in-bar tab reordering intact. Detach only after leaving the tab bar.
                if(!bar->rect().adjusted(-8,-8,8,8).contains(mouse->pos())){
                    const int index=m_pressIndex;
                    m_pressIndex=-1;
                    detachTab(index);
                    return true;
                }
            }
        }else if(event->type()==QEvent::MouseButtonRelease){
            m_pressIndex=-1;
            m_dragging=false;
        }else if(event->type()==QEvent::MouseButtonDblClick){
            auto* mouse=static_cast<QMouseEvent*>(event);
            const int index=bar->tabAt(mouse->pos());
            if(index>=0){detachTab(index);return true;}
        }
    }

    if(m_detached.contains(qobject_cast<QWidget*>(watched)) && event->type()==QEvent::Close){
        auto* window=qobject_cast<QWidget*>(watched);
        reattach(window);
        return false;
    }
    return QObject::eventFilter(watched,event);
}

void DetachableTabWidget::detachTab(int index)
{
    if(!m_tabs || index<0 || index>=m_tabs->count())return;
    QWidget* page=m_tabs->widget(index);
    if(!page)return;
    DetachedPage item;
    item.page=page;
    item.title=m_tabs->tabText(index);
    item.icon=m_tabs->tabIcon(index);
    item.originalIndex=index;

    m_tabs->removeTab(index);
    auto* window=new QWidget(nullptr,Qt::Window);
    window->setAttribute(Qt::WA_DeleteOnClose,true);
    window->setWindowTitle(item.title);
    window->setWindowIcon(item.icon);
    window->resize(qMax(760,page->width()),qMax(520,page->height()));
    auto* layout=new QVBoxLayout(window);
    layout->setContentsMargins(4,4,4,4);
    page->setParent(window);
    layout->addWidget(page);
    item.window=window;
    m_detached.insert(window,item);
    window->installEventFilter(this);
    window->show();
    window->raise();
}

void DetachableTabWidget::reattach(QWidget* window)
{
    if(!window || !m_detached.contains(window) || !m_tabs)return;
    const DetachedPage item=m_detached.take(window);
    window->removeEventFilter(this);
    if(item.page){
        if(window->layout())window->layout()->removeWidget(item.page);
        item.page->setParent(m_tabs);
        const int index=qBound(0,item.originalIndex,m_tabs->count());
        m_tabs->insertTab(index,item.page,item.icon,item.title);
        m_tabs->setCurrentWidget(item.page);
    }
}

void DetachableTabWidget::reattachAll()
{
    const auto windows=m_detached.keys();
    for(QWidget* window:windows){
        reattach(window);
        if(window)window->deleteLater();
    }
}
