#pragma once

#include <QObject>
#include <QPoint>
#include <QString>

class QBoxLayout;
class QFrame;
class QHBoxLayout;
class QSplitter;
class QWidget;

// Wraps an existing data panel with a compact drag handle. Drag the handle (or
// double-click it) to float the original widget; closing the floating window
// reattaches the exact same widget, so live data/state is never duplicated.
class DetachablePanelManager : public QObject {
public:
    explicit DetachablePanelManager(QWidget* panel,
                                    const QString& title,
                                    const QString& settingsKey=QString(),
                                    QObject* parent=nullptr);
    ~DetachablePanelManager() override;

    bool eventFilter(QObject* watched,QEvent* event) override;

    void detachPanel();
    void reattachPanel();
    void setPanelVisible(bool visible);
    bool isPanelVisible() const;
    void setCompactHeader(bool compact);
    void addHeaderWidget(QWidget* widget);
    bool isDetached() const{return m_detached;}
    QWidget* container() const;

private:
    void buildWrapper();
    void restoreFloatingState();
    void saveFloatingGeometry();
    QPoint mouseGlobalPosition(class QMouseEvent* event) const;
    void reattachPanelInternal(bool persistState);

    QWidget* m_panel=nullptr;
    QWidget* m_originalParent=nullptr;
    QFrame* m_wrapper=nullptr;
    QFrame* m_header=nullptr;
    class QLabel* m_titleLabel=nullptr;
    class QLabel* m_hintLabel=nullptr;
    class QPushButton* m_floatButton=nullptr;
    QHBoxLayout* m_headerLayout=nullptr;
    QSplitter* m_splitter=nullptr;
    QBoxLayout* m_boxLayout=nullptr;
    int m_originalIndex=-1;
    QString m_title;
    QString m_settingsKey;
    bool m_detached=false;
    bool m_desiredVisible=true;
    bool m_pressed=false;
    bool m_draggingFloating=false;
    QPoint m_pressGlobal;
    QPoint m_windowOffset;
};
