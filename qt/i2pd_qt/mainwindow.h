#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#ifndef ANDROID
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QMenu>
#endif

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

//#ifndef ANDROID
//    void setVisible(bool visible);
//#endif

private slots:
    void handleQuitButton();
    void handleGracefulQuitButton();
    void handleGracefulQuitTimerEvent();
#ifndef ANDROID
    void setIcon();
    void iconActivated(QSystemTrayIcon::ActivationReason reason);
    void toggleVisibilitySlot();
#endif

private:
#ifndef ANDROID
    void createActions();
    void createTrayIcon();
#endif

    QWidget *centralWidget;
    QWidget *verticalLayoutWidget;
    QVBoxLayout *verticalLayout1;
    QPushButton *quitButton;
    QPushButton *gracefulQuitButton;

#ifndef ANDROID
    bool quitting;
    QAction *toggleWindowVisibleAction;
    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;
#endif

protected:
#ifndef ANDROID
    void closeEvent(QCloseEvent *event);
#endif
};

#endif // MAINWINDOW_H
