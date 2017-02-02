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
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
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
    void showStatusPage();
    void showSettingsPage();
    void showTunnelsPage();
    void showRestartPage();
    void showQuitPage();

private:
#ifndef ANDROID
    void createActions();
    void createTrayIcon();
    bool quitting;
    QAction *toggleWindowVisibleAction;
    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;
#endif

    Ui::MainWindow* ui;

protected:
#ifndef ANDROID
    void closeEvent(QCloseEvent *event);
#endif
    void resizeEvent(QResizeEvent* event);
    void onResize();

    void initFileChooser(QLineEdit* fileNameLineEdit, QPushButton* fileBrowsePushButton);
    void initFolderChooser(QLineEdit* folderLineEdit, QPushButton* folderBrowsePushButton);
    void initCombobox(QComboBox* comboBox);
    void initIPAddressBox(QLineEdit* addressLineEdit, QString fieldNameTranslated);
    void initTCPPortBox(QLineEdit* portLineEdit, QString fieldNameTranslated);
    void initCheckBox(QCheckBox* checkBox);
    void initIntegerBox(QLineEdit* numberLineEdit);
    void initStringBox(QLineEdit* lineEdit);

    void loadAllConfigs();
    void saveAllConfigs();

};

#endif // MAINWINDOW_H
