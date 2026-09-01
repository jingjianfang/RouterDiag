#pragma once

#include <QObject>
#include <QHash>
#include <QIcon>
#include <QPoint>

class QTabWidget;
class QWidget;

// Adds drag-to-float behavior to an existing QTabWidget without copying page state.
// Closing the floating window reattaches the original page widget.
class DetachableTabWidget : public QObject {
    Q_OBJECT
public:
    explicit DetachableTabWidget(QTabWidget* tabs,QObject* parent=nullptr);
    ~DetachableTabWidget() override;

    bool eventFilter(QObject* watched,QEvent* event) override;
    void detachTab(int index);
    void reattachAll();

private:
    struct DetachedPage {
        QWidget* page=nullptr;
        QWidget* window=nullptr;
        QString title;
        QIcon icon;
        int originalIndex=0;
    };

    void reattach(QWidget* window);

    QTabWidget* m_tabs=nullptr;
    QPoint m_pressPos;
    int m_pressIndex=-1;
    bool m_dragging=false;
    QHash<QWidget*,DetachedPage> m_detached;
};
