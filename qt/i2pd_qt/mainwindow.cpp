#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QTimer>
#include "RouterContext.h"
#ifndef ANDROID
#include <QtDebug>
#endif

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
#ifndef ANDROID
    ,quitting(false)
#endif
{
    ui->setupUi(this);
    resize(800, 480);
    //ui->stackedWidget->setCurrentIndex(4);//quit page
    ui->stackedWidget->setCurrentIndex(1);//sett. page

#ifndef ANDROID
    createActions();
    createTrayIcon();
#endif

    QObject::connect(ui->fastQuitPushButton, SIGNAL(released()), this, SLOT(handleQuitButton()));
    QObject::connect(ui->gracefulQuitPushButton, SIGNAL(released()), this, SLOT(handleGracefulQuitButton()));

#ifndef ANDROID
    QObject::connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
                this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

    setIcon();
    trayIcon->show();
#endif

    //QMetaObject::connectSlotsByName(this);
}

#ifndef ANDROID
void MainWindow::createActions() {
    toggleWindowVisibleAction = new QAction(tr("&Toggle the window"), this);
    connect(toggleWindowVisibleAction, SIGNAL(triggered()), this, SLOT(toggleVisibilitySlot()));

    //quitAction = new QAction(tr("&Quit"), this);
    //connect(quitAction, SIGNAL(triggered()), QApplication::instance(), SLOT(quit()));
}

void MainWindow::toggleVisibilitySlot() {
    setVisible(!isVisible());
}

void MainWindow::createTrayIcon() {
    trayIconMenu = new QMenu(this);
    trayIconMenu->addAction(toggleWindowVisibleAction);
    //trayIconMenu->addSeparator();
    //trayIconMenu->addAction(quitAction);

    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setContextMenu(trayIconMenu);
}

void MainWindow::setIcon() {
    QIcon icon(":/images/icon.png");
    trayIcon->setIcon(icon);
    setWindowIcon(icon);

    trayIcon->setToolTip(QApplication::translate("MainWindow", "i2pd", 0));
}

void MainWindow::iconActivated(QSystemTrayIcon::ActivationReason reason) {
    switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
    case QSystemTrayIcon::MiddleClick:
        setVisible(!isVisible());
        break;
    default:
        qDebug() << "MainWindow::iconActivated(): unknown reason: " << reason << endl;
        break;
    }
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if(quitting){ QMainWindow::closeEvent(event); return; }
    if (trayIcon->isVisible()) {
        QMessageBox::information(this, tr("i2pd"),
                                 tr("The program will keep running in the "
                                    "system tray. To gracefully terminate the program, "
                                    "choose <b>Graceful Quit</b> at the main i2pd window."));
        hide();
        event->ignore();
    }
}
#endif

void MainWindow::handleQuitButton() {
    qDebug("Quit pressed. Hiding the main window");
#ifndef ANDROID
    quitting=true;
#endif
    close();
    QApplication::instance()->quit();
}

void MainWindow::handleGracefulQuitButton() {
    qDebug("Graceful Quit pressed.");
    ui->gracefulQuitPushButton->setText(QApplication::translate("MainWindow", "Graceful quit is in progress", 0));
    ui->gracefulQuitPushButton->setEnabled(false);
    ui->gracefulQuitPushButton->adjustSize();
    ui->quitPage->adjustSize();
    i2p::context.SetAcceptsTunnels (false); // stop accpting tunnels
    QTimer::singleShot(10*60*1000/*millis*/, this, SLOT(handleGracefulQuitTimerEvent()));
}

void MainWindow::handleGracefulQuitTimerEvent() {
    qDebug("Hiding the main window");
#ifndef ANDROID
    quitting=true;
#endif
    close();
    qDebug("Performing quit");
    QApplication::instance()->quit();
}

MainWindow::~MainWindow()
{
    qDebug("Destroying main window");
    //QMessageBox::information(0, "Debug", "mw destructor 1");
    //delete ui;
    //QMessageBox::information(0, "Debug", "mw destructor 2");
}
