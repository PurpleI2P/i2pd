#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QTimer>
#include "RouterContext.h"
#ifndef ANDROID
#include <QtDebug>
#endif
#include <QScrollBar>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
#ifndef ANDROID
    ,quitting(false)
#endif
{
    ui->setupUi(this);

    //TODO handle resizes and change the below into resize() call
    setFixedSize(width(), 480);
    onResize();

    ui->stackedWidget->setCurrentIndex(0);
    ui->settingsScrollArea->resize(ui->settingsContentsGridLayout->sizeHint().width()+10,ui->settingsScrollArea->height());
    QScrollBar* const barSett = ui->settingsScrollArea->verticalScrollBar();
    //QSize szSettContents = ui->settingsContentsGridLayout->minimumSize();
    int w = 683;
    int h = 3000;
    ui->settingsContents->setFixedSize(w, h);
    ui->settingsContents->resize(w, h);
    //ui->settingsContents->adjustSize();

    /*
    QPalette pal(palette());
    pal.setColor(QPalette::Background, Qt::red);
    ui->settingsContents->setAutoFillBackground(true);
    ui->settingsContents->setPalette(pal);
    */

    //ui->settingsScrollArea->adjustSize();
    ui->tunnelsScrollAreaWidgetContents->setFixedSize(
                ui->tunnelsScrollArea->width() - barSett->width(), 0);

#ifndef ANDROID
    createActions();
    createTrayIcon();
#endif

    QObject::connect(ui->statusPagePushButton, SIGNAL(released()), this, SLOT(showStatusPage()));
    QObject::connect(ui->settingsPagePushButton, SIGNAL(released()), this, SLOT(showSettingsPage()));

    QObject::connect(ui->tunnelsPagePushButton, SIGNAL(released()), this, SLOT(showTunnelsPage()));
    QObject::connect(ui->restartPagePushButton, SIGNAL(released()), this, SLOT(showRestartPage()));
    QObject::connect(ui->quitPagePushButton, SIGNAL(released()), this, SLOT(showQuitPage()));

    QObject::connect(ui->fastQuitPushButton, SIGNAL(released()), this, SLOT(handleQuitButton()));
    QObject::connect(ui->gracefulQuitPushButton, SIGNAL(released()), this, SLOT(handleGracefulQuitButton()));

    initFileChooser(ui->configFileLineEdit, ui->configFileBrowsePushButton);
    initFileChooser(ui->tunnelsConfigFileLineEdit, ui->tunnelsConfigFileBrowsePushButton);
    initFileChooser(ui->pidFileLineEdit, ui->pidFileBrowsePushButton);
    initFileChooser(ui->logFileLineEdit, ui->logFileBrowsePushButton);
    initFileChooser(ui->httpProxyKeyFileLineEdit, ui->httpProxyKeyFilePushButton);
    initFileChooser(ui->socksProxyKeyFileLineEdit, ui->socksProxyKeyFilePushButton);
    initFileChooser(ui->i2pControlCertFileLineEdit, ui->i2pControlCertFileBrowsePushButton);
    initFileChooser(ui->i2pControlKeyFileLineEdit, ui->i2pControlKeyFileBrowsePushButton);
    initFileChooser(ui->reseedFileLineEdit, ui->reseedFileBrowsePushButton);

    initFolderChooser(ui->dataFolderLineEdit, ui->dataFolderBrowsePushButton);

    initCombobox(ui->logLevelComboBox);

    initIPAddressBox(ui->routerExternalHostLineEdit, tr("Router external address -> Host"));
    initTCPPortBox(ui->routerExternalPortLineEdit, tr("Router external address -> Port"));

    initCheckBox(ui->ipv6CheckBox);
    initCheckBox(ui->notransitCheckBox);
    initCheckBox(ui->floodfillCheckBox);
    initIntegerBox(ui->bandwidthLineEdit);
    initStringBox(ui->familyLineEdit);
    initIntegerBox(ui->netIdLineEdit);
	
    initCheckBox(ui->insomniaCheckBox);

    initCheckBox(ui->webconsoleEnabledCheckBox);
    initIPAddressBox(ui->webconsoleAddrLineEdit, tr("HTTP webconsole -> IP address"));
    initTCPPortBox(ui->webconsolePortLineEdit, tr("HTTP webconsole -> Port"));
    initCheckBox(ui->webconsoleBasicAuthCheckBox);
    initStringBox(ui->webconsoleUserNameLineEditBasicAuth);
    initStringBox(ui->webconsolePasswordLineEditBasicAuth);

    initCheckBox(ui->httpProxyEnabledCheckBox);
    initIPAddressBox(ui->httpProxyAddressLineEdit, tr("HTTP proxy -> IP address"));
    initTCPPortBox(ui->httpProxyPortLineEdit, tr("HTTP proxy -> Port"));
    initIntegerBox(ui->httpProxyInboundTunnelsLenLineEdit);
    initIntegerBox(ui->httpProxyInboundTunnQuantityLineEdit);
    initIntegerBox(ui->httpProxyOutBoundTunnLenLineEdit);
    initIntegerBox(ui->httpProxyOutboundTunnQuantityLineEdit);

    initCheckBox(ui->socksProxyEnabledCheckBox);
    initIPAddressBox(ui->socksProxyAddressLineEdit, tr("Socks proxy -> IP address"));
    initTCPPortBox(ui->socksProxyPortLineEdit, tr("Socks proxy -> Port"));
    initIntegerBox(ui->socksProxyInboundTunnelsLenLineEdit);
    initIntegerBox(ui->socksProxyInboundTunnQuantityLineEdit);
    initIntegerBox(ui->socksProxyOutBoundTunnLenLineEdit);
    initIntegerBox(ui->socksProxyOutboundTunnQuantityLineEdit);
    initIPAddressBox(ui->outproxyAddressLineEdit, tr("Socks proxy -> Outproxy address"));
    initTCPPortBox(ui->outproxyPortLineEdit, tr("Socks proxy -> Outproxy port"));

    initCheckBox(ui->samEnabledCheckBox);
    initIPAddressBox(ui->samAddressLineEdit, tr("SAM -> IP address"));
    initTCPPortBox(ui->samPortLineEdit, tr("SAM -> Port"));

    initCheckBox(ui->bobEnabledCheckBox);
    initIPAddressBox(ui->bobAddressLineEdit, tr("BOB -> IP address"));
    initTCPPortBox(ui->bobPortLineEdit, tr("BOB -> Port"));

    initCheckBox(ui->i2cpEnabledCheckBox);
    initIPAddressBox(ui->i2cpAddressLineEdit, tr("I2CP -> IP address"));
    initTCPPortBox(ui->i2cpPortLineEdit, tr("I2CP -> Port"));

    initCheckBox(ui->i2pControlEnabledCheckBox);
    initIPAddressBox(ui->i2pControlAddressLineEdit, tr("I2PControl -> IP address"));
    initTCPPortBox(ui->i2pControlPortLineEdit, tr("I2PControl -> Port"));
    initStringBox(ui->i2pControlPasswordLineEdit);
	
    initCheckBox(ui->enableUPnPCheckBox);
    initStringBox(ui->upnpNameLineEdit);
	
    initCheckBox(ui->useElGamalPrecomputedTablesCheckBox);
	
    initCheckBox(ui->reseedVerifyCheckBox);
    initStringBox(ui->reseedURLsLineEdit);
	
    initStringBox(ui->addressbookDefaultURLLineEdit);
    initStringBox(ui->addressbookSubscriptionsURLslineEdit);
	
    initIntegerBox(ui->maxNumOfTransitTunnelsLineEdit);
    initIntegerBox(ui->maxNumOfOpenFilesLineEdit);
    initIntegerBox(ui->coreFileMaxSizeNumberLineEdit);

    loadAllConfigs();

#ifndef ANDROID
    QObject::connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
                this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

    setIcon();
    trayIcon->show();
#endif

    //QMetaObject::connectSlotsByName(this);
}

void MainWindow::showStatusPage(){ui->stackedWidget->setCurrentIndex(0);}
void MainWindow::showSettingsPage(){ui->stackedWidget->setCurrentIndex(1);}
void MainWindow::showTunnelsPage(){ui->stackedWidget->setCurrentIndex(2);}
void MainWindow::showRestartPage(){ui->stackedWidget->setCurrentIndex(3);}
void MainWindow::showQuitPage(){ui->stackedWidget->setCurrentIndex(4);}

//TODO
void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    onResize();
}

//TODO
void MainWindow::onResize()
{
    if(isVisible()){
        ui->horizontalLayoutWidget->resize(ui->horizontalLayoutWidget->width(), height());

        //status
        ui->statusPage->resize(ui->statusPage->width(), height());

        //tunnels
        ui->tunnelsPage->resize(ui->tunnelsPage->width(), height());
        ui->verticalLayoutWidget_6->resize(ui->verticalLayoutWidget_6->width(), height()-20);
        /*ui->tunnelsScrollArea->resize(ui->tunnelsScrollArea->width(),
                                      ui->verticalLayoutWidget_6->height()-ui->label_5->height());*/
    }
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
    QTimer::singleShot(10*60*1000//millis
        , this, SLOT(handleGracefulQuitTimerEvent()));
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

void MainWindow::initFileChooser(QLineEdit* fileNameLineEdit, QPushButton* fileBrowsePushButton){}
void MainWindow::initFolderChooser(QLineEdit* folderLineEdit, QPushButton* folderBrowsePushButton){}
void MainWindow::initCombobox(QComboBox* comboBox){}
void MainWindow::initIPAddressBox(QLineEdit* addressLineEdit, QString fieldNameTranslated){}
void MainWindow::initTCPPortBox(QLineEdit* portLineEdit, QString fieldNameTranslated){}
void MainWindow::initCheckBox(QCheckBox* checkBox){}
void MainWindow::initIntegerBox(QLineEdit* numberLineEdit){}
void MainWindow::initStringBox(QLineEdit* lineEdit){}

void MainWindow::loadAllConfigs(){}
void MainWindow::saveAllConfigs(){}
