#include "mainwindow.h"
#include "I2pdQtUtil.h"
#include "AboutDialog.h"
#include "ui_mainwindow.h"
#include "ui_statusbuttons.h"
#include "ui_routercommandswidget.h"
#include "ui_generalsettingswidget.h"
#include <QScrollBar>
#include <QMessageBox>
#include <QTimer>
#include <QFile>
#include <QFileDialog>

#include <QApplication>
#include <QScreen>
#include <QStyleHints>
#include <QScreen>
#include <QWindow>

#include <assert.h>

#include "RouterContext.h"
#include "Config.h"
#include "FS.h"
#include "Log.h"
#include "RouterContext.h"
#include "Transports.h"

#include "HTTPServer.h"

#ifndef ANDROID
# include <QtDebug>
#endif

#include "DaemonQT.h"
#include "SignatureTypeComboboxFactory.h"

#include "logviewermanager.h"

#include "DelayedSaveManagerImpl.h"
#include "SaverImpl.h"


std::string programOptionsWriterCurrentSection;

MainWindow::MainWindow(std::shared_ptr<std::iostream> logStream_, QWidget *parent) :
    QMainWindow(parent)
    ,currentLocalDestinationB32("")
    ,logStream(logStream_)
    ,delayedSaveManagerPtr(new DelayedSaveManagerImpl())
    ,dataSerial(DelayedSaveManagerImpl::INITIAL_DATA_SERIAL)
    ,wasSelectingAtStatusMainPage(false)
    ,showHiddenInfoStatusMainPage(false)
    ,logViewerManagerPtr(nullptr)
#ifndef ANDROID
    ,quitting(false)
#endif
    ,ui(new Ui::MainWindow)
    ,statusButtonsUI(new Ui::StatusButtonsForm)
    ,routerCommandsUI(new Ui::routerCommandsWidget)
    ,uiSettings(new Ui::GeneralSettingsContentsForm)
    ,routerCommandsParent(new QWidget(this))
    ,widgetlocks()
    ,i2pController(nullptr)
    ,configItems()
    ,datadir()
    ,confpath()
    ,tunconfpath()
    ,tunnelConfigs()
    ,tunnelsPageUpdateListener(this)
    ,saverPtr(new SaverImpl(this, &configItems, &tunnelConfigs))

{
    assert(delayedSaveManagerPtr!=nullptr);
    assert(saverPtr!=nullptr);

    ui->setupUi(this);
    statusButtonsUI->setupUi(ui->statusButtonsPane);
    routerCommandsUI->setupUi(routerCommandsParent);
    uiSettings->setupUi(ui->settingsContents);

    ui->aboutHrefLabel->setText("<html><head/><body><p><a href='about:i2pd_qt'><span style='text-decoration:none;color:#a0a0a0;'>"
                                "<span style='font-weight:500;'>i2pd_qt</span><br/>Version " I2PD_VERSION " · About...</span></a></p></body></html>");

    routerCommandsParent->hide();
    ui->verticalLayout_2->addWidget(routerCommandsParent);
    //,statusHtmlUI(new Ui::StatusHtmlPaneForm)
    //statusHtmlUI->setupUi(lastStatusWidgetui->statusWidget);
    ui->statusButtonsPane->setFixedSize(171,300);
    ui->verticalLayout->setGeometry(QRect(0,0,171,ui->verticalLayout->geometry().height()));
    //ui->statusButtonsPane->adjustSize();
    //ui->centralWidget->adjustSize();
    setWindowTitle(QApplication::translate("AppTitle","I2PD"));

    //TODO handle resizes and change the below into resize() call
    constexpr auto WINDOW_HEIGHT = 610;
    setFixedHeight(WINDOW_HEIGHT);
    ui->centralWidget->setFixedHeight(WINDOW_HEIGHT);
    onResize();

    ui->stackedWidget->setCurrentIndex(0);
    ui->settingsScrollArea->resize(uiSettings->settingsContentsQVBoxLayout->sizeHint().width()+10,380);
    //QScrollBar* const barSett = ui->settingsScrollArea->verticalScrollBar();
    constexpr auto w = 683;
    constexpr auto h = 4550;
    ui->settingsContents->setFixedSize(w, h);
    ui->settingsContents->setGeometry(QRect(0,0,w,h));

    /*
    QPalette pal(palette());
    pal.setColor(QPalette::Background, Qt::red);
    ui->settingsContents->setAutoFillBackground(true);
    ui->settingsContents->setPalette(pal);
    */
    QPalette pal(palette());
    pal.setColor(QPalette::Background, Qt::red);
    ui->wrongInputLabel->setAutoFillBackground(true);
    ui->wrongInputLabel->setPalette(pal);
    ui->wrongInputLabel->setMaximumHeight(ui->wrongInputLabel->sizeHint().height());
    ui->wrongInputLabel->setVisible(false);

    settingsTitleLabelNominalHeight = ui->settingsTitleLabel->height();
#ifndef ANDROID
    createActions();
    createTrayIcon();
#endif

    textBrowser = new TextBrowserTweaked1(this);
    //textBrowser->setOpenExternalLinks(false);
    textBrowser->setOpenLinks(false);
    /*textBrowser->setTextInteractionFlags(textBrowser->textInteractionFlags()|
                                         Qt::LinksAccessibleByMouse|Qt::LinksAccessibleByKeyboard|
                                         Qt::TextSelectableByMouse|Qt::TextSelectableByKeyboard);*/
    ui->verticalLayout_2->addWidget(textBrowser);
    childTextBrowser = new TextBrowserTweaked1(this);
    //childTextBrowser->setOpenExternalLinks(false);
    childTextBrowser->setOpenLinks(false);
    connect(textBrowser, SIGNAL(anchorClicked(const QUrl&)), this, SLOT(anchorClickedHandler(const QUrl&)));
    connect(childTextBrowser, SIGNAL(anchorClicked(const QUrl&)), this, SLOT(anchorClickedHandler(const QUrl&)));
    pageWithBackButton = new PageWithBackButton(this, childTextBrowser);
    ui->verticalLayout_2->addWidget(pageWithBackButton);
    pageWithBackButton->hide();
    connect(pageWithBackButton, SIGNAL(backReleased()), this, SLOT(backClickedFromChild()));
    scheduleStatusPageUpdates();

    QObject::connect(ui->statusPagePushButton, SIGNAL(released()), this, SLOT(showStatusMainPage()));
    showStatusMainPage();
    QObject::connect(statusButtonsUI->mainPagePushButton, SIGNAL(released()), this, SLOT(showStatusMainPage()));
    QObject::connect(statusButtonsUI->routerCommandsPushButton, SIGNAL(released()), this, SLOT(showStatus_commands_Page()));
    QObject::connect(statusButtonsUI->localDestinationsPushButton, SIGNAL(released()), this, SLOT(showStatus_local_destinations_Page()));
    QObject::connect(statusButtonsUI->leasesetsPushButton, SIGNAL(released()), this, SLOT(showStatus_leasesets_Page()));
    QObject::connect(statusButtonsUI->tunnelsPushButton, SIGNAL(released()), this, SLOT(showStatus_tunnels_Page()));
    QObject::connect(statusButtonsUI->transitTunnelsPushButton, SIGNAL(released()), this, SLOT(showStatus_transit_tunnels_Page()));
    QObject::connect(statusButtonsUI->transportsPushButton, SIGNAL(released()), this, SLOT(showStatus_transports_Page()));
    QObject::connect(statusButtonsUI->i2pTunnelsPushButton, SIGNAL(released()), this, SLOT(showStatus_i2p_tunnels_Page()));
    QObject::connect(statusButtonsUI->samSessionsPushButton, SIGNAL(released()), this, SLOT(showStatus_sam_sessions_Page()));

    QObject::connect(textBrowser, SIGNAL(mouseReleased()), this, SLOT(statusHtmlPageMouseReleased()));
    QObject::connect(textBrowser, SIGNAL(selectionChanged()), this, SLOT(statusHtmlPageSelectionChanged()));

    QObject::connect(routerCommandsUI->runPeerTestPushButton, SIGNAL(released()), this, SLOT(runPeerTest()));
    QObject::connect(routerCommandsUI->acceptTransitTunnelsPushButton, SIGNAL(released()), this, SLOT(enableTransit()));
    QObject::connect(routerCommandsUI->declineTransitTunnelsPushButton, SIGNAL(released()), this, SLOT(disableTransit()));

    QObject::connect(ui->aboutHrefLabel, SIGNAL(linkActivated(const QString &)), this, SLOT(showAboutBox(const QString &)));

    QObject::connect(ui->logViewerPushButton, SIGNAL(released()), this, SLOT(showLogViewerPage()));

    QObject::connect(ui->settingsPagePushButton, SIGNAL(released()), this, SLOT(showSettingsPage()));

    QObject::connect(ui->tunnelsPagePushButton, SIGNAL(released()), this, SLOT(showTunnelsPage()));
    QObject::connect(ui->restartPagePushButton, SIGNAL(released()), this, SLOT(showRestartPage()));
    QObject::connect(ui->quitPagePushButton, SIGNAL(released()), this, SLOT(showQuitPage()));

    QObject::connect(ui->fastQuitPushButton, SIGNAL(released()), this, SLOT(handleQuitButton()));
    QObject::connect(ui->gracefulQuitPushButton, SIGNAL(released()), this, SLOT(handleGracefulQuitButton()));

    QObject::connect(ui->doRestartI2PDPushButton, SIGNAL(released()), this, SLOT(handleDoRestartButton()));

#   define OPTION(section,option,defaultValueGetter) ConfigOption(QString(section),QString(option))

    initFileChooser(    OPTION("","conf",[](){return "";}), uiSettings->configFileLineEdit, uiSettings->configFileBrowsePushButton, false, true);
    initFileChooser(    OPTION("","tunconf",[](){return "";}), uiSettings->tunnelsConfigFileLineEdit, uiSettings->tunnelsConfigFileBrowsePushButton, false);
    initFileChooser(    OPTION("","pidfile",[]{return "";}), uiSettings->pidFileLineEdit, uiSettings->pidFileBrowsePushButton, false);

    uiSettings->logDestinationComboBox->clear();
    uiSettings->logDestinationComboBox->insertItems(0, QStringList()
        << QApplication::translate("MainWindow", "syslog", 0)
        << QApplication::translate("MainWindow", "stdout", 0)
        << QApplication::translate("MainWindow", "file", 0)
    );
    initLogDestinationCombobox(   OPTION("","log",[]{return "";}), uiSettings->logDestinationComboBox);
#ifdef I2PD_QT_RELEASE
    uiSettings->logDestinationComboBox->setEnabled(false); // #1593
#endif

    logFileNameOption=initFileChooser(    OPTION("","logfile",[]{return "";}), uiSettings->logFileLineEdit, uiSettings->logFileBrowsePushButton, false);
    initLogLevelCombobox(OPTION("","loglevel",[]{return "";}), uiSettings->logLevelComboBox);

    QObject::connect(uiSettings->logLevelComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(syncLogLevel(int)));

    initCheckBox(       OPTION("","logclftime",[]{return "false";}), uiSettings->logclftimeCheckBox);//"Write full CLF-formatted date and time to log (default: write only time)"
    initFolderChooser(  OPTION("","datadir",[]{return "";}), uiSettings->dataFolderLineEdit, uiSettings->dataFolderBrowsePushButton);
    initIPAddressBox(   OPTION("","host",[]{return "";}), uiSettings->routerExternalHostLineEdit, tr("Router external address -> Host"));
    initTCPPortBox(     OPTION("","port",[]{return "";}), uiSettings->routerExternalPortLineEdit, tr("Router external address -> Port"));
    daemonOption=initNonGUIOption(   OPTION("","daemon",[]{return "";}));
    serviceOption=initNonGUIOption(   OPTION("","service",[]{return "";}));
    initStringBox(      OPTION("","ifname4",[]{return "";}), uiSettings->ifname4LineEdit);//Network interface to bind to for IPv4
    initStringBox(      OPTION("","ifname6",[]{return "";}), uiSettings->ifname6LineEdit);//Network interface to bind to for IPv6
    initCheckBox(       OPTION("","nat",[]{return "true";}), uiSettings->natCheckBox);//If true, assume we are behind NAT. true by default
    initCheckBox(       OPTION("","ipv4",[]{return "true";}), uiSettings->ipv4CheckBox);//Enable communication through IPv4. true by default
    initCheckBox(       OPTION("","ipv6",[]{return "false";}), uiSettings->ipv6CheckBox);
    initCheckBox(       OPTION("","notransit",[]{return "false";}), uiSettings->notransitCheckBox);
    initCheckBox(       OPTION("","floodfill",[]{return "false";}), uiSettings->floodfillCheckBox);
    initStringBox(      OPTION("","bandwidth",[]{return "";}), uiSettings->bandwidthLineEdit);
    initIntegerBox(     OPTION("","share",[]{return "100";}), uiSettings->shareLineEdit, tr("Share"));//Max % of bandwidth limit for transit. 0-100. 100 by default
    initStringBox(      OPTION("","family",[]{return "";}), uiSettings->familyLineEdit);
    initIntegerBox(     OPTION("","netid",[]{return "2";}), uiSettings->netIdLineEdit, tr("NetID"));
    initCheckBox(       OPTION("","ssu",[]{return "true";}), uiSettings->ssuCheckBox);//Enable SSU transport protocol (use UDP). true by default
    initCheckBox(       OPTION("","reservedrange",[]{return "true";}), uiSettings->reservedrange_checkbox);

#ifdef Q_OS_WIN
    initNonGUIOption(   OPTION("","svcctl",[]{return "";}));
    initCheckBox(       OPTION("","insomnia",[]{return "";}), uiSettings->insomniaCheckBox);
    initNonGUIOption(   OPTION("","close",[]{return "";}));
#else
    uiSettings->insomniaCheckBox->setEnabled(false);
#endif

    initCheckBox(       OPTION("http","enabled",[]{return "true";}), uiSettings->webconsoleEnabledCheckBox);
    initIPAddressBox(   OPTION("http","address",[]{return "";}), uiSettings->webconsoleAddrLineEdit, tr("HTTP webconsole -> IP address"));
    initTCPPortBox(     OPTION("http","port",[]{return "7070";}), uiSettings->webconsolePortLineEdit, tr("HTTP webconsole -> Port"));
    initCheckBox(       OPTION("http","auth",[]{return "";}), uiSettings->webconsoleBasicAuthCheckBox);
    initStringBox(      OPTION("http","user",[]{return "i2pd";}), uiSettings->webconsoleUserNameLineEditBasicAuth);
    initStringBox(      OPTION("http","pass",[]{return "";}), uiSettings->webconsolePasswordLineEditBasicAuth);
    initCheckBox(       OPTION("http","strictheaders",[]{return "true";}), uiSettings->httpStrictHeadersCheckBox);//Enable strict host checking on WebUI. true by default
    initStringBox(      OPTION("http","hostname",[]{return "localhost";}), uiSettings->httpHostnameLineEdit);//Expected hostname for WebUI (default: localhost)

    initCheckBox(       OPTION("httpproxy","enabled",[]{return "";}), uiSettings->httpProxyEnabledCheckBox);
    initIPAddressBox(   OPTION("httpproxy","address",[]{return "";}), uiSettings->httpProxyAddressLineEdit, tr("HTTP proxy -> IP address"));
    initTCPPortBox(     OPTION("httpproxy","port",[]{return "4444";}), uiSettings->httpProxyPortLineEdit, tr("HTTP proxy -> Port"));
    initCheckBox(       OPTION("httpproxy","addresshelper",[]{return "true";}), uiSettings->httpProxyAddressHelperCheckBox);//Enable address helper (jump). true by default
    initFileChooser(    OPTION("httpproxy","keys",[]{return "";}), uiSettings->httpProxyKeyFileLineEdit, uiSettings->httpProxyKeyFilePushButton, false);
    initSignatureTypeCombobox(OPTION("httpproxy","signaturetype",[]{return "7";}), uiSettings->comboBox_httpPorxySignatureType);
    initStringBox(     OPTION("httpproxy","inbound.length",[]{return "3";}), uiSettings->httpProxyInboundTunnelsLenLineEdit);
    initStringBox(     OPTION("httpproxy","inbound.quantity",[]{return "5";}), uiSettings->httpProxyInboundTunnQuantityLineEdit);
    initStringBox(     OPTION("httpproxy","outbound.length",[]{return "3";}), uiSettings->httpProxyOutBoundTunnLenLineEdit);
    initStringBox(     OPTION("httpproxy","outbound.quantity",[]{return "5";}), uiSettings->httpProxyOutboundTunnQuantityLineEdit);
    initStringBox(     OPTION("httpproxy","outproxy",[]{return "";}), uiSettings->httpProxyOutproxyLineEdit);//HTTP proxy upstream out proxy url (like http://false.i2p)
    initStringBox(     OPTION("httpproxy","i2cp.leaseSetType",[]{return "1";}), uiSettings->httpProxyI2cpLeaseSetTypeLineEdit);//Type of LeaseSet to be sent. 1, 3 or 5. 1 by default
    initStringBox(     OPTION("httpproxy","i2cp.leaseSetEncType",[]{return "";}), uiSettings->httpProxyI2cpLeaseSetEncTypeLineEdit);//Comma separated encryption types to be used in LeaseSet type 3 or 5

    initCheckBox(       OPTION("socksproxy","enabled",[]{return "";}), uiSettings->socksProxyEnabledCheckBox);
    initIPAddressBox(   OPTION("socksproxy","address",[]{return "";}), uiSettings->socksProxyAddressLineEdit, tr("Socks proxy -> IP address"));
    initTCPPortBox(     OPTION("socksproxy","port",[]{return "4447";}), uiSettings->socksProxyPortLineEdit, tr("Socks proxy -> Port"));
    initFileChooser(    OPTION("socksproxy","keys",[]{return "";}), uiSettings->socksProxyKeyFileLineEdit, uiSettings->socksProxyKeyFilePushButton, false);
    initSignatureTypeCombobox(OPTION("socksproxy","signaturetype",[]{return "7";}), uiSettings->comboBox_socksProxySignatureType);
    initStringBox(     OPTION("socksproxy","inbound.length",[]{return "";}), uiSettings->socksProxyInboundTunnelsLenLineEdit);
    initStringBox(     OPTION("socksproxy","inbound.quantity",[]{return "";}), uiSettings->socksProxyInboundTunnQuantityLineEdit);
    initStringBox(     OPTION("socksproxy","outbound.length",[]{return "";}), uiSettings->socksProxyOutBoundTunnLenLineEdit);
    initStringBox(     OPTION("socksproxy","outbound.quantity",[]{return "";}), uiSettings->socksProxyOutboundTunnQuantityLineEdit);
    initCheckBox(      OPTION("socksproxy","outproxy.enabled",[]{return "false";}), uiSettings->socksOutproxyEnabledCheckBox);
    initIPAddressBox(  OPTION("socksproxy","outproxy",[]{return "127.0.0.1";}), uiSettings->outproxyAddressLineEdit, tr("Socks proxy -> Outproxy address"));
    initTCPPortBox(    OPTION("socksproxy","outproxyport",[]{return "9050";}), uiSettings->outproxyPortLineEdit, tr("Socks proxy -> Outproxy port"));
    initStringBox(     OPTION("socksproxy","i2cp.leaseSetType",[]{return "1";}), uiSettings->socksProxyI2cpLeaseSetTypeLineEdit);//Type of LeaseSet to be sent. 1, 3 or 5. 1 by default
    initStringBox(     OPTION("socksproxy","i2cp.leaseSetEncType",[]{return "";}), uiSettings->socksProxyI2cpLeaseSetEncTypeLineEdit);//Comma separated encryption types to be used in LeaseSet type 3 or 5

    initCheckBox(       OPTION("sam","enabled",[]{return "false";}), uiSettings->samEnabledCheckBox);
    initIPAddressBox(   OPTION("sam","address",[]{return "";}), uiSettings->samAddressLineEdit, tr("SAM -> IP address"));
    initTCPPortBox(     OPTION("sam","port",[]{return "7656";}), uiSettings->samPortLineEdit, tr("SAM -> Port"));
    initCheckBox(       OPTION("sam","singlethread",[]{return "true";}), uiSettings->samSingleThreadCheckBox);//If false every SAM session runs in own thread. true by default

    initCheckBox(       OPTION("bob","enabled",[]{return "false";}), uiSettings->bobEnabledCheckBox);
    initIPAddressBox(   OPTION("bob","address",[]{return "";}), uiSettings->bobAddressLineEdit, tr("BOB -> IP address"));
    initTCPPortBox(     OPTION("bob","port",[]{return "2827";}), uiSettings->bobPortLineEdit, tr("BOB -> Port"));

    initCheckBox(       OPTION("i2cp","enabled",[]{return "false";}), uiSettings->i2cpEnabledCheckBox);
    initIPAddressBox(   OPTION("i2cp","address",[]{return "";}), uiSettings->i2cpAddressLineEdit, tr("I2CP -> IP address"));
    initTCPPortBox(     OPTION("i2cp","port",[]{return "7654";}), uiSettings->i2cpPortLineEdit, tr("I2CP -> Port"));
    //initCheckBox(       OPTION("i2cp","singlethread",[]{return "true";}), uiSettings->i2cpSingleThreadCheckBox);//If false every I2CP session runs in own thread. true by default

    initCheckBox(       OPTION("i2pcontrol","enabled",[]{return "false";}), uiSettings->i2pControlEnabledCheckBox);
    initIPAddressBox(   OPTION("i2pcontrol","address",[]{return "";}), uiSettings->i2pControlAddressLineEdit, tr("I2PControl -> IP address"));
    initTCPPortBox(     OPTION("i2pcontrol","port",[]{return "7650";}), uiSettings->i2pControlPortLineEdit, tr("I2PControl -> Port"));
    initStringBox(      OPTION("i2pcontrol","password",[]{return "";}), uiSettings->i2pControlPasswordLineEdit);
    initFileChooser(    OPTION("i2pcontrol","cert",[]{return "i2pcontrol.crt.pem";}), uiSettings->i2pControlCertFileLineEdit, uiSettings->i2pControlCertFileBrowsePushButton, true);
    initFileChooser(    OPTION("i2pcontrol","key",[]{return "i2pcontrol.key.pem";}), uiSettings->i2pControlKeyFileLineEdit, uiSettings->i2pControlKeyFileBrowsePushButton, true);

    initCheckBox(       OPTION("upnp","enabled",[]{return "true";}), uiSettings->enableUPnPCheckBox);
    initStringBox(      OPTION("upnp","name",[]{return "I2Pd";}), uiSettings->upnpNameLineEdit);

    initCheckBox(       OPTION("precomputation","elgamal",[]{return "false";}), uiSettings->useElGamalPrecomputedTablesCheckBox);

    initCheckBox(       OPTION("reseed","verify",[]{return "";}), uiSettings->reseedVerifyCheckBox);
    initFileChooser(    OPTION("reseed","file",[]{return "";}), uiSettings->reseedFileLineEdit, uiSettings->reseedFileBrowsePushButton, true);
    initStringBox(      OPTION("reseed","urls",[]{return "";}), uiSettings->reseedURLsLineEdit);
    initFileChooser(    OPTION("reseed","zipfile",[]{return "";}), uiSettings->reseedZipFileLineEdit, uiSettings->reseedZipFileBrowsePushButton, true); //Path to local .zip file to reseed from
    initUInt16Box(      OPTION("reseed","threshold",[]{return "25";}), uiSettings->reseedThresholdNumberLineEdit, tr("reseedThreshold")); //Minimum number of known routers before requesting reseed. 25 by default
    initStringBox(      OPTION("reseed","proxy",[]{return "";}), uiSettings->reseedProxyLineEdit);//URL for https/socks reseed proxy

    initStringBox(      OPTION("addressbook","defaulturl",[]{return "";}), uiSettings->addressbookDefaultURLLineEdit);
    initStringBox(      OPTION("addressbook","subscriptions",[]{return "";}), uiSettings->addressbookSubscriptionsURLslineEdit);

    initUInt16Box(     OPTION("limits","transittunnels",[]{return "2500";}), uiSettings->maxNumOfTransitTunnelsLineEdit, tr("maxNumberOfTransitTunnels"));
    initUInt16Box(     OPTION("limits","openfiles",[]{return "0";}), uiSettings->maxNumOfOpenFilesLineEdit, tr("maxNumberOfOpenFiles"));
    initUInt32Box(     OPTION("limits","coresize",[]{return "0";}), uiSettings->coreFileMaxSizeNumberLineEdit, tr("coreFileMaxSize"));

    initCheckBox(       OPTION("trust","enabled",[]{return "false";}), uiSettings->checkBoxTrustEnable);
    initStringBox(      OPTION("trust","family",[]{return "";}), uiSettings->lineEditTrustFamily);
    initStringBox(      OPTION("trust","routers",[]{return "";}), uiSettings->lineEditTrustRouters);
    initCheckBox(       OPTION("trust","hidden",[]{return "false";}), uiSettings->checkBoxTrustHidden);

    initCheckBox(       OPTION("websockets","enabled",[]{return "false";}), uiSettings->checkBoxWebsocketsEnable); //Enable websocket server. Disabled by default
    initIPAddressBox(   OPTION("websockets","address",[]{return "127.0.0.1";}), uiSettings->websocketsAddressLineEdit, tr("Websockets -> IP address")); //Address to bind websocket server on. 127.0.0.1 by default
    initTCPPortBox(     OPTION("websockets","port",[]{return "7666";}), uiSettings->websocketsPortLineEdit, tr("Websockets -> Port")); //Port to bind websocket server on. 7666 by default

    initIntegerBox(     OPTION("exploratory","inbound.length",[]{return "2";}), uiSettings->exploratoryInboundTunnelsLengthNumberLineEdit, tr("exploratoryInboundTunnelsLength"));//Exploratory inbound tunnels length. 2 by default
    initIntegerBox(     OPTION("exploratory","inbound.quantity",[]{return "3";}), uiSettings->exploratoryInboundTunnelsQuantityNumberLineEdit, tr("exploratoryInboundTunnelsQuantity"));//Exploratory inbound tunnels quantity. 3 by default
    initIntegerBox(     OPTION("exploratory","outbound.length",[]{return "2";}), uiSettings->exploratoryOutboundTunnelsLengthNumberLineEdit, tr("exploratoryOutboundTunnelsLength"));//Exploratory outbound tunnels length. 2 by default
    initIntegerBox(     OPTION("exploratory","outbound.quantity",[]{return "3";}), uiSettings->exploratoryOutboundTunnelsQuantityNumberLineEdit, tr("exploratoryOutboundTunnelsQuantity"));//Exploratory outbound tunnels length. 3 by default

    initCheckBox(       OPTION("ntcp2","enabled",[]{return "true";}), uiSettings->checkBoxNtcp2Enable); //Enable NTCP2. Enabled by default
    initCheckBox(       OPTION("ntcp2","published",[]{return "false";}), uiSettings->checkBoxNtcp2Published); //Enable incoming NTCP2 connections. Disabled by default
    initTCPPortBox(     OPTION("ntcp2","port",[]{return "0";}), uiSettings->ntcp2PortLineEdit, tr("NTCP2 -> Port")); //Port to listen for incoming NTCP2 connections (default: auto)
    initIPAddressBox(   OPTION("ntcp2","addressv6",[]{return "::";}), uiSettings->ntcp2AddressV6LineEdit, tr("NTCP2 -> IPv6 address")); //External IPv6 for incoming connections
    initStringBox(      OPTION("ntcp2","proxy",[]{return "";}), uiSettings->lineEditNtcp2Proxy); //Specify proxy server for NTCP2. Should be http://address:port or socks://address:port

    initCheckBox(       OPTION("nettime","enabled",[]{return "false";}), uiSettings->checkBoxNettimeEnable); //Enable NTP sync. Disabled by default
    initStringBox(      OPTION("nettime","ntpservers",[]{return "pool.ntp.org";}), uiSettings->lineEditNetTimeNtpServers); //Comma-separated list of NTP servers. pool.ntp.org by default
    initIntegerBox(     OPTION("nettime","ntpsyncinterval",[]{return "72";}), uiSettings->nettimeNtpSyncIntervalNumberLineEdit, tr("nettimeNtpSyncInterval")); //NTP time sync interval in hours. 72 by default

    initCheckBox(       OPTION("persist","profiles",[]{return "true";}), uiSettings->checkBoxPersistProfiles);//Enable peer profile persisting to disk. Enabled by default
#   undef OPTION

    //widgetlocks.add(new widgetlock(widget,lockbtn));


    // #1593
#ifdef I2PD_QT_RELEASE
    uiSettings->logDestComboEditPushButton->setEnabled(false);
#else
    widgetlocks.add(new widgetlock(uiSettings->logDestinationComboBox,uiSettings->logDestComboEditPushButton));
#endif

    widgetlocks.add(new widgetlock(uiSettings->logLevelComboBox,uiSettings->logLevelComboEditPushButton));
    widgetlocks.add(new widgetlock(uiSettings->comboBox_httpPorxySignatureType,uiSettings->httpProxySignTypeComboEditPushButton));
    widgetlocks.add(new widgetlock(uiSettings->comboBox_socksProxySignatureType,uiSettings->socksProxySignTypeComboEditPushButton));

    loadAllConfigs(saverPtr);

    QObject::connect(saverPtr, SIGNAL(reloadTunnelsConfigAndUISignal(const QString)),
                     this, SLOT(reloadTunnelsConfigAndUI_QString(const QString)));

    delayedSaveManagerPtr->setSaver(saverPtr);
    delayedSaveManagerPtr->start();

    QObject::connect(uiSettings->logDestinationComboBox, SIGNAL(currentIndexChanged(const QString &)),
                     this, SLOT(logDestinationComboBoxValueChanged(const QString &)));
    logDestinationComboBoxValueChanged(uiSettings->logDestinationComboBox->currentText());

    ui->tunnelsScrollAreaWidgetContents->setGeometry(QRect(0, 0, 621, 451));

    ui->tunnelsScrollAreaWidgetContents->setStyleSheet("QGroupBox { " \
                                                   "    font: bold;" \
                                                   "    border: 1px solid silver;" \
                                                   "    border-radius: 6px;" \
                                                   "    margin-top: 6px;" \
                                                   "}" \
                                                   "QGroupBox::title {" \
                                                   "    subcontrol-origin: margin;" \
                                                   "    left: 7px;" \
                                                   "    padding: 0px 5px 0px 5px;" \
                                                   "}");

    appendTunnelForms("");

    uiSettings->configFileLineEdit->setEnabled(false);
    uiSettings->configFileBrowsePushButton->setEnabled(false);
    uiSettings->configFileLineEdit->setText(confpath);
    uiSettings->tunnelsConfigFileLineEdit->setText(tunconfpath);

    for(QList<MainWindowItem*>::iterator it = configItems.begin(); it!= configItems.end(); ++it) {
        MainWindowItem* item = *it;
        item->installListeners(this);
    }

    QObject::connect(uiSettings->tunnelsConfigFileLineEdit, SIGNAL(textChanged(const QString &)),
                     this, SLOT(reloadTunnelsConfigAndUI()));
    QObject::connect(ui->addServerTunnelPushButton, SIGNAL(released()), this, SLOT(addServerTunnelPushButtonReleased()));
    QObject::connect(ui->addClientTunnelPushButton, SIGNAL(released()), this, SLOT(addClientTunnelPushButtonReleased()));


#ifndef ANDROID
    QObject::connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
                this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

    setIcon();
    trayIcon->show();
#endif

    logViewerManagerPtr=new LogViewerManager(logStream_,ui->logViewerTextEdit,this);
    assert(logViewerManagerPtr!=nullptr);
    //onLoggingOptionsChange();
    //QMetaObject::connectSlotsByName(this);
}

void MainWindow::logDestinationComboBoxValueChanged(const QString & text) {
    bool fileEnabled = text==QString("file");
    uiSettings->logFileLineEdit->setEnabled(fileEnabled);
    uiSettings->logFileBrowsePushButton->setEnabled(fileEnabled);
}


void MainWindow::updateRouterCommandsButtons() {
    bool acceptsTunnels = i2p::context.AcceptsTunnels ();
    routerCommandsUI->declineTransitTunnelsPushButton->setEnabled(acceptsTunnels);
    routerCommandsUI->acceptTransitTunnelsPushButton->setEnabled(!acceptsTunnels);
}

void MainWindow::showStatusPage(StatusPage newStatusPage){
    ui->stackedWidget->setCurrentIndex(0);
    setStatusButtonsVisible(true);
    statusPage=newStatusPage;
    showHiddenInfoStatusMainPage=false;
    if(newStatusPage!=StatusPage::commands){
        textBrowser->setHtml(getStatusPageHtml(false));
        textBrowser->show();
        routerCommandsParent->hide();
        pageWithBackButton->hide();
    }else{
        routerCommandsParent->show();
        textBrowser->hide();
        pageWithBackButton->hide();
        updateRouterCommandsButtons();
    }
    wasSelectingAtStatusMainPage=false;
}

void MainWindow::showAboutBox(const QString & href) {
    AboutDialog dialog(this);

    /*
    //doesn't work on older qt5: ‘class QStyleHints’ has no member named ‘showIsMaximized’
    if (!QGuiApplication::styleHints()->showIsFullScreen() && !QGuiApplication::styleHints()->showIsMaximized()) {
        const QWindow * windowHandle = dialog.windowHandle();
        qDebug()<<"AboutDialog windowHandle ptr: "<<(size_t)windowHandle<<endl;
        const QScreen * screen = windowHandle?windowHandle->screen():nullptr; //Qt 5.14+: dialog.screen()
        qDebug()<<"AboutDialog screen ptr: "<<(size_t)screen<<endl;
        if (screen) {
            const QRect availableGeometry = screen->availableGeometry();
            //dialog.resize(availableGeometry.width() / 3, availableGeometry.height() * 2 / 3);
            dialog.move((availableGeometry.width() - dialog.width()) / 2,
                        (availableGeometry.height() - dialog.height()) / 2);
        }
    }
    */

    (void) dialog.exec();
}

void MainWindow::showLogViewerPage(){ui->stackedWidget->setCurrentIndex(1);setStatusButtonsVisible(false);}
void MainWindow::showSettingsPage(){ui->stackedWidget->setCurrentIndex(2);setStatusButtonsVisible(false);}
void MainWindow::showTunnelsPage(){ui->stackedWidget->setCurrentIndex(3);setStatusButtonsVisible(false);}
void MainWindow::showRestartPage(){ui->stackedWidget->setCurrentIndex(4);setStatusButtonsVisible(false);}
void MainWindow::showQuitPage(){ui->stackedWidget->setCurrentIndex(5);setStatusButtonsVisible(false);}

void MainWindow::setStatusButtonsVisible(bool visible) {
    ui->statusButtonsPane->setVisible(visible);
}

// see also: HTTPServer.cpp
QString MainWindow::getStatusPageHtml(bool showHiddenInfo) {
    std::stringstream s;

    s << "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">";

    switch (statusPage) {
    case main_page:
        i2p::http::ShowStatus(s, showHiddenInfo, i2p::http::OutputFormatEnum::forQtUi);
        break;
    case commands: break;
    case local_destinations: i2p::http::ShowLocalDestinations(s);break;
    case leasesets: i2p::http::ShowLeasesSets(s); break;
    case tunnels: i2p::http::ShowTunnels(s); break;
    case transit_tunnels: i2p::http::ShowTransitTunnels(s); break;
    case transports: i2p::http::ShowTransports(s); break;
    case i2p_tunnels: i2p::http::ShowI2PTunnels(s); break;
    case sam_sessions: i2p::http::ShowSAMSessions(s); break;
    default: assert(false); break;
    }

    std::string str = s.str();
    return QString::fromStdString(str);
}

void MainWindow::showStatusMainPage() { showStatusPage(StatusPage::main_page); }
void MainWindow::showStatus_commands_Page() { showStatusPage(StatusPage::commands); }
void MainWindow::showStatus_local_destinations_Page() { showStatusPage(StatusPage::local_destinations); }
void MainWindow::showStatus_leasesets_Page() { showStatusPage(StatusPage::leasesets); }
void MainWindow::showStatus_tunnels_Page() { showStatusPage(StatusPage::tunnels); }
void MainWindow::showStatus_transit_tunnels_Page() { showStatusPage(StatusPage::transit_tunnels); }
void MainWindow::showStatus_transports_Page() { showStatusPage(StatusPage::transports); }
void MainWindow::showStatus_i2p_tunnels_Page() { showStatusPage(StatusPage::i2p_tunnels); }
void MainWindow::showStatus_sam_sessions_Page() { showStatusPage(StatusPage::sam_sessions); }


void MainWindow::scheduleStatusPageUpdates() {
    statusPageUpdateTimer = new QTimer(this);
    connect(statusPageUpdateTimer, SIGNAL(timeout()), this, SLOT(updateStatusPage()));
    statusPageUpdateTimer->start(10*1000/*millis*/);
}

void MainWindow::statusHtmlPageMouseReleased() {
    if(wasSelectingAtStatusMainPage){
        QString selection = textBrowser->textCursor().selectedText();
        if(!selection.isEmpty()&&!selection.isNull())return;
    }
    showHiddenInfoStatusMainPage=!showHiddenInfoStatusMainPage;
    textBrowser->setHtml(getStatusPageHtml(showHiddenInfoStatusMainPage));
}

void MainWindow::statusHtmlPageSelectionChanged() {
    wasSelectingAtStatusMainPage=true;
}

void MainWindow::updateStatusPage() {
    showHiddenInfoStatusMainPage=false;
    textBrowser->setHtml(getStatusPageHtml(showHiddenInfoStatusMainPage));
}


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
    QIcon icon(":icons/mask");
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
    delayedSaveManagerPtr->appExiting();
    qDebug("Performing quit");
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

void MainWindow::handleDoRestartButton() {
    qDebug()<<"Do Restart pressed.";
    emit i2pController->restartDaemon();
}


void MainWindow::handleGracefulQuitTimerEvent() {
    qDebug("Hiding the main window");
#ifndef ANDROID
    quitting=true;
#endif
    close();
    delayedSaveManagerPtr->appExiting();
    qDebug("Performing quit");
    QApplication::instance()->quit();
}

MainWindow::~MainWindow()
{
    qDebug("Destroying main window");
    delete statusPageUpdateTimer;
    delete delayedSaveManagerPtr;
    delete saverPtr;
    for(QList<MainWindowItem*>::iterator it = configItems.begin(); it!= configItems.end(); ++it) {
        MainWindowItem* item = *it;
        item->deleteLater();
    }
    configItems.clear();
    //QMessageBox::information(0, "Debug", "mw destructor 1");
    //delete ui;
    //QMessageBox::information(0, "Debug", "mw destructor 2");
}

FileChooserItem* MainWindow::initFileChooser(ConfigOption option, QLineEdit* fileNameLineEdit, QPushButton* fileBrowsePushButton, bool requireExistingFile, bool readOnly){
    FileChooserItem* retVal;
    retVal=new FileChooserItem(option, fileNameLineEdit, fileBrowsePushButton, this, requireExistingFile, readOnly);
    MainWindowItem* super=retVal;
    configItems.append(super);
    return retVal;
}
void MainWindow::initFolderChooser(ConfigOption option, QLineEdit* folderLineEdit, QPushButton* folderBrowsePushButton){
    configItems.append(new FolderChooserItem(option, folderLineEdit, folderBrowsePushButton, this, true));
}
/*void MainWindow::initCombobox(ConfigOption option, QComboBox* comboBox){
    configItems.append(new ComboBoxItem(option, comboBox));
    QObject::connect(comboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(saveAllConfigs()));
}*/
void MainWindow::initLogDestinationCombobox(ConfigOption option, QComboBox* comboBox){
    configItems.append(new LogDestinationComboBoxItem(option, comboBox));
}
void MainWindow::initLogLevelCombobox(ConfigOption option, QComboBox* comboBox){
    configItems.append(new LogLevelComboBoxItem(option, comboBox));
}
void MainWindow::initSignatureTypeCombobox(ConfigOption option, QComboBox* comboBox){
    configItems.append(new SignatureTypeComboBoxItem(option, comboBox));
}
void MainWindow::initIPAddressBox(ConfigOption option, QLineEdit* addressLineEdit, QString fieldNameTranslated){
    configItems.append(new IPAddressStringItem(option, addressLineEdit, fieldNameTranslated, this));
}
void MainWindow::initTCPPortBox(ConfigOption option, QLineEdit* portLineEdit, QString fieldNameTranslated){
    configItems.append(new TCPPortStringItem(option, portLineEdit, fieldNameTranslated, this));
}
void MainWindow::initCheckBox(ConfigOption option, QCheckBox* checkBox) {
    configItems.append(new CheckBoxItem(option, checkBox));
}
void MainWindow::initIntegerBox(ConfigOption option, QLineEdit* numberLineEdit, QString fieldNameTranslated){
    configItems.append(new IntegerStringItem(option, numberLineEdit, fieldNameTranslated, this));
}
void MainWindow::initUInt32Box(ConfigOption option, QLineEdit* numberLineEdit, QString fieldNameTranslated){
    configItems.append(new UInt32StringItem(option, numberLineEdit, fieldNameTranslated, this));
}
void MainWindow::initUInt16Box(ConfigOption option, QLineEdit* numberLineEdit, QString fieldNameTranslated){
    configItems.append(new UInt16StringItem(option, numberLineEdit, fieldNameTranslated, this));
}
void MainWindow::initStringBox(ConfigOption option, QLineEdit* lineEdit){
    configItems.append(new BaseStringItem(option, lineEdit, QString(), this));
}
NonGUIOptionItem* MainWindow::initNonGUIOption(ConfigOption option) {
    NonGUIOptionItem * retValue;
    configItems.append(retValue=new NonGUIOptionItem(option));
    return retValue;
}

void MainWindow::loadAllConfigs(SaverImpl* saverPtr){

    //BORROWED FROM ??? //TODO move this code into single location
    std::string config;  i2p::config::GetOption("conf",    config);
    std::string datadir; i2p::config::GetOption("datadir", datadir);
    bool service = false;
#ifndef _WIN32
    i2p::config::GetOption("service", service);
#endif
    i2p::fs::DetectDataDir(datadir, service);
    i2p::fs::Init();

    datadir = i2p::fs::GetDataDir();
    // TODO: drop old name detection in v2.8.0
    if (config == "")
    {
        config = i2p::fs::DataDirPath("i2p.conf");
        if (i2p::fs::Exists (config)) {
            LogPrint(eLogWarning, "Daemon: please rename i2p.conf to i2pd.conf here: ", config);
        } else {
            config = i2p::fs::DataDirPath("i2pd.conf");
            /*if (!i2p::fs::Exists (config)) {}*/
        }
    }

    //BORROWED FROM ClientContext.cpp //TODO move this code into single location
    std::string tunConf; i2p::config::GetOption("tunconf", tunConf);
    if (tunConf == "") {
        // TODO: cleanup this in 2.8.0
        tunConf = i2p::fs::DataDirPath ("tunnels.cfg");
        if (i2p::fs::Exists(tunConf)) {
            LogPrint(eLogWarning, "FS: please rename tunnels.cfg -> tunnels.conf here: ", tunConf);
        } else {
            tunConf = i2p::fs::DataDirPath ("tunnels.conf");
        }
    }

    this->confpath = config.c_str();
    this->datadir = datadir.c_str();
    this->tunconfpath = tunConf.c_str();

    saverPtr->setConfPath(this->confpath);
    saverPtr->setTunnelsConfPath(this->tunconfpath);

    for(QList<MainWindowItem*>::iterator it = configItems.begin(); it!= configItems.end(); ++it) {
        MainWindowItem* item = *it;
        item->loadFromConfigOption();
    }

    ReadTunnelsConfig();

    //onLoggingOptionsChange();
}

void MainWindow::layoutTunnels() {

    int height=0;
    ui->tunnelsScrollAreaWidgetContents->setGeometry(0,0,0,0);
    for(std::map<std::string, TunnelConfig*>::iterator it = tunnelConfigs.begin(); it != tunnelConfigs.end(); ++it) {
        //const std::string& name=it->first;
        TunnelConfig* tunconf = it->second;
        TunnelPane * tunnelPane=tunconf->getTunnelPane();
        if(!tunnelPane)continue;
        int h=tunnelPane->height();
        height+=h;
        //qDebug() << "tun.height:" << height << "sz:" <<  tunnelPanes.size();
        //int h=tunnelPane->appendClientTunnelForm(ctc, ui->tunnelsScrollAreaWidgetContents, tunnelPanes.size(), height);
    }
    //qDebug() << "tun.setting height:" << height;
    ui->tunnelsScrollAreaWidgetContents->setGeometry(QRect(0, 0, 621, height));
    /*QList<QWidget*> childWidgets = ui->tunnelsScrollAreaWidgetContents->findChildren<QWidget*>();
    foreach(QWidget* widget, childWidgets)
        widget->show();*/
}

void MainWindow::deleteTunnelFromUI(std::string tunnelName, TunnelConfig* cnf) {
    TunnelPane* tp = cnf->getTunnelPane();
    if(!tp)return;
    tunnelPanes.remove(tp);
    tp->deleteWidget();
    layoutTunnels();
}

/** returns false iff not valid items present and save was aborted */
bool MainWindow::saveAllConfigs(bool reloadAfterSave, FocusEnum focusOn, std::string tunnelNameToFocus, QWidget* widgetToFocus){
    QString cannotSaveSettings = QApplication::tr("Cannot save settings.");
    programOptionsWriterCurrentSection="";
    /*if(!logFileNameOption->lineEdit->text().trimmed().isEmpty())logOption->optionValue=boost::any(std::string("file"));
    else logOption->optionValue=boost::any(std::string("stdout"));*/
    daemonOption->optionValue=boost::any(false);
    serviceOption->optionValue=boost::any(false);

    for(QList<MainWindowItem*>::iterator it = configItems.begin(); it!= configItems.end(); ++it) {
        MainWindowItem* item = *it;
        bool alreadyDisplayedIfWrong=false;
        if(!item->isValid(alreadyDisplayedIfWrong)){
            if(!alreadyDisplayedIfWrong)
                highlightWrongInput(
                        QApplication::tr("Invalid value for")+" "+item->getConfigOption().section+"::"+item->getConfigOption().option+". "+item->getRequirementToBeValid()+" "+cannotSaveSettings,
                        WrongInputPageEnum::generalSettingsPage,
                        item->getWidgetToFocus());
            return false;
        }
    }
    delayedSaveManagerPtr->delayedSave(reloadAfterSave, ++dataSerial, focusOn, tunnelNameToFocus, widgetToFocus);//TODO does dataSerial work? //FIXME

    //onLoggingOptionsChange();
    return true;
}

void FileChooserItem::pushButtonReleased() {
    QString fileName = lineEdit->text().trimmed();
    fileName = requireExistingFile ?
            QFileDialog::getOpenFileName(nullptr, tr("Open File"), fileName, tr("All Files (*.*)")) :
            QFileDialog::getSaveFileName(nullptr, tr("Open File"), fileName, tr("All Files (*.*)"));
    if(fileName.length()>0)lineEdit->setText(fileName);
}
void FolderChooserItem::pushButtonReleased() {
    QString fileName = lineEdit->text().trimmed();
    assert(requireExistingFile);
    fileName = QFileDialog::getExistingDirectory(nullptr, tr("Open Folder"), fileName);
    if(fileName.length()>0)lineEdit->setText(fileName);
}

void BaseStringItem::installListeners(MainWindow *mainWindow) {
    QObject::connect(lineEdit, SIGNAL(textChanged(const QString &)), mainWindow, SLOT(updated()));
}
bool BaseStringItem::isValid(bool & alreadyDisplayedIfWrong) {
    alreadyDisplayedIfWrong=true;
    return ::isValidSingleLine(lineEdit, WrongInputPageEnum::generalSettingsPage, mainWindow);
}

void ComboBoxItem::installListeners(MainWindow *mainWindow) {
    QObject::connect(comboBox, SIGNAL(currentIndexChanged(int)), mainWindow, SLOT(updated()));
}
void CheckBoxItem::installListeners(MainWindow *mainWindow) {
    QObject::connect(checkBox, SIGNAL(stateChanged(int)), mainWindow, SLOT(updated()));
}

void MainWindow::updated() {
    ui->wrongInputLabel->setVisible(false);
    adjustSizesAccordingToWrongLabel();

    bool correct = applyTunnelsUiToConfigs();
    if(!correct) return;
    saveAllConfigs(false, FocusEnum::noFocus);
}

void MainWindowItem::installListeners(MainWindow *mainWindow) {}

void MainWindow::appendTunnelForms(std::string tunnelNameToFocus) {
    int height=0;
    ui->tunnelsScrollAreaWidgetContents->setGeometry(0,0,0,0);
    for(std::map<std::string, TunnelConfig*>::iterator it = tunnelConfigs.begin(); it != tunnelConfigs.end(); ++it) {
        const std::string& name=it->first;
        TunnelConfig* tunconf = it->second;
        ServerTunnelConfig* stc = tunconf->asServerTunnelConfig();
        if(stc){
            ServerTunnelPane * tunnelPane=new ServerTunnelPane(&tunnelsPageUpdateListener, stc, ui->wrongInputLabel, ui->wrongInputLabel, this);
            tunconf->setTunnelPane(tunnelPane);
            int h=tunnelPane->appendServerTunnelForm(stc, ui->tunnelsScrollAreaWidgetContents, tunnelPanes.size(), height);
            height+=h;
            //qDebug() << "tun.height:" << height << "sz:" <<  tunnelPanes.size();
            tunnelPanes.push_back(tunnelPane);
            if(name==tunnelNameToFocus){
                tunnelPane->getNameLineEdit()->setFocus();
                ui->tunnelsScrollArea->ensureWidgetVisible(tunnelPane->getNameLineEdit());
            }
            continue;
        }
        ClientTunnelConfig* ctc = tunconf->asClientTunnelConfig();
        if(ctc){
            ClientTunnelPane * tunnelPane=new ClientTunnelPane(&tunnelsPageUpdateListener, ctc, ui->wrongInputLabel, ui->wrongInputLabel, this);
            tunconf->setTunnelPane(tunnelPane);
            int h=tunnelPane->appendClientTunnelForm(ctc, ui->tunnelsScrollAreaWidgetContents, tunnelPanes.size(), height);
            height+=h;
            //qDebug() << "tun.height:" << height << "sz:" <<  tunnelPanes.size();
            tunnelPanes.push_back(tunnelPane);
            if(name==tunnelNameToFocus){
                tunnelPane->getNameLineEdit()->setFocus();
                ui->tunnelsScrollArea->ensureWidgetVisible(tunnelPane->getNameLineEdit());
            }
            continue;
        }
        throw "unknown TunnelConfig subtype";
    }
    //qDebug() << "tun.setting height:" << height;
    ui->tunnelsScrollAreaWidgetContents->setGeometry(QRect(0, 0, 621, height));
    QList<QWidget*> childWidgets = ui->tunnelsScrollAreaWidgetContents->findChildren<QWidget*>();
    foreach(QWidget* widget, childWidgets)
        widget->show();
}
void MainWindow::deleteTunnelForms() {
    for(std::list<TunnelPane*>::iterator it = tunnelPanes.begin(); it != tunnelPanes.end(); ++it) {
        TunnelPane* tp = *it;
        ServerTunnelPane* stp = tp->asServerTunnelPane();
        if(stp){
            stp->deleteServerTunnelForm();
            delete stp;
            continue;
        }
        ClientTunnelPane* ctp = tp->asClientTunnelPane();
        if(ctp){
            ctp->deleteClientTunnelForm();
            delete ctp;
            continue;
        }
        throw "unknown TunnelPane subtype";
    }
    tunnelPanes.clear();
}

bool MainWindow::applyTunnelsUiToConfigs() {
    for(std::list<TunnelPane*>::iterator it = tunnelPanes.begin(); it != tunnelPanes.end(); ++it) {
        TunnelPane* tp = *it;
        if(!tp->applyDataFromUIToTunnelConfig())return false;
    }
    return true;
}

void MainWindow::reloadTunnelsConfigAndUI_QString(QString tunnelNameToFocus) {
    reloadTunnelsConfigAndUI(tunnelNameToFocus.toStdString(), nullptr);
}

void MainWindow::reloadTunnelsConfigAndUI(std::string tunnelNameToFocus, QWidget* widgetToFocus) {
    deleteTunnelForms();
    for (std::map<std::string,TunnelConfig*>::iterator it=tunnelConfigs.begin(); it!=tunnelConfigs.end(); ++it) {
        TunnelConfig* tunconf = it->second;
        delete tunconf;
    }
    tunnelConfigs.clear();
    ReadTunnelsConfig();
    appendTunnelForms(tunnelNameToFocus);
}

void MainWindow::TunnelsPageUpdateListenerMainWindowImpl::updated(std::string oldName, TunnelConfig* tunConf) {
    if(oldName!=tunConf->getName()) {
        //name has changed
        std::map<std::string,TunnelConfig*>::const_iterator it=mainWindow->tunnelConfigs.find(oldName);
        if(it!=mainWindow->tunnelConfigs.end())mainWindow->tunnelConfigs.erase(it);
        mainWindow->tunnelConfigs[tunConf->getName()]=tunConf;
        mainWindow->saveAllConfigs(true, FocusEnum::focusOnTunnelName, tunConf->getName());
    }
    else
        mainWindow->saveAllConfigs(false, FocusEnum::noFocus);
}

void MainWindow::TunnelsPageUpdateListenerMainWindowImpl::needsDeleting(std::string oldName){
    mainWindow->DeleteTunnelNamed(oldName);
}

void MainWindow::addServerTunnelPushButtonReleased() {
    CreateDefaultServerTunnel();
}

void MainWindow::addClientTunnelPushButtonReleased() {
    CreateDefaultClientTunnel();
}

void MainWindow::setI2PController(i2p::qt::Controller* controller_) {
    this->i2pController = controller_;
}

void MainWindow::runPeerTest() {
    i2p::transport::transports.PeerTest();
}

void MainWindow::enableTransit() {
    i2p::context.SetAcceptsTunnels(true);
    updateRouterCommandsButtons();
}

void MainWindow::disableTransit() {
    i2p::context.SetAcceptsTunnels(false);
    updateRouterCommandsButtons();
}

void MainWindow::anchorClickedHandler(const QUrl & link) {
    QString debugStr=QString()+"anchorClicked: "+"\""+link.toString()+"\"";
    qDebug()<<debugStr;
    //QMessageBox::information(this, "", debugStr);

    QString str=link.toString();
    std::map<std::string, std::string> params;
    i2p::http::URL url;
    url.parse(str.toStdString());
    url.parse_query(params);
    const std::string page = params["page"];
    const std::string cmd = params["cmd"];
    if (page == "sam_session") {
        pageWithBackButton->show();
        textBrowser->hide();
        std::stringstream s;
        i2p::http::ShowSAMSession (s, params["sam_id"]);
        childTextBrowser->setHtml(QString::fromStdString(s.str()));
    } else if (page == "local_destination") {
        std::string b32 = params["b32"];
        currentLocalDestinationB32 = b32;
        pageWithBackButton->show();
        textBrowser->hide();
        std::stringstream s;
        std::string strstd = currentLocalDestinationB32;
        i2p::http::ShowLocalDestination(s,strstd,0);
        childTextBrowser->setHtml(QString::fromStdString(s.str()));
    } else if (page == "i2cp_local_destination") {
        pageWithBackButton->show();
        textBrowser->hide();
        std::stringstream s;
        i2p::http::ShowI2CPLocalDestination (s, params["i2cp_id"]);
        childTextBrowser->setHtml(QString::fromStdString(s.str()));
    } else if(cmd == "closestream") {
        std::string b32 = params["b32"];
        uint32_t streamID = std::stoul(params["streamID"], nullptr);

        i2p::data::IdentHash ident;
        ident.FromBase32 (b32);
        auto dest = i2p::client::context.FindLocalDestination (ident);

        if (streamID) {
            if (dest) {
                if(dest->DeleteStream (streamID))
                    QMessageBox::information(
                                this,
                                QApplication::tr("Success"),
                                QApplication::tr("<HTML><b>SUCCESS</b>: Stream closed"));
                else
                    QMessageBox::critical(
                                this,
                                QApplication::tr("Error"),
                                QApplication::tr("<HTML><b>ERROR</b>: Stream not found or already was closed"));
            }
            else
                QMessageBox::critical(
                            this,
                            QApplication::tr("Error"),
                            QApplication::tr("<HTML><b>ERROR</b>: Destination not found"));
        }
        else
            QMessageBox::critical(
                        this,
                        QApplication::tr("Error"),
                        QApplication::tr("<HTML><b>ERROR</b>: StreamID is null"));
        std::stringstream s;
        std::string strstd = currentLocalDestinationB32;
        i2p::http::ShowLocalDestination(s,strstd,0);
        childTextBrowser->setHtml(QString::fromStdString(s.str()));
   }
}

void MainWindow::backClickedFromChild() {
    showStatusPage(statusPage);
}

void MainWindow::adjustSizesAccordingToWrongLabel() {
    constexpr auto HEIGHT = 581;
    constexpr auto WIDTH = 707;
    if(ui->wrongInputLabel->isVisible()) {
        int dh = ui->wrongInputLabel->height()+ui->verticalLayout_7->layout()->spacing();
        ui->verticalLayout_7->invalidate();
        ui->wrongInputLabel->adjustSize();
        ui->stackedWidget->adjustSize();
        const auto height = HEIGHT - dh;
        ui->stackedWidget->setFixedHeight(height);
        ui->settingsPage->setFixedHeight(height);
        ui->verticalLayoutWidget_4->setGeometry(QRect(0, 0, WIDTH, height));
        ui->stackedWidget->setFixedHeight(height);
        ui->settingsScrollArea->setFixedHeight(height-settingsTitleLabelNominalHeight-ui->verticalLayout_4->spacing());
        ui->settingsTitleLabel->setFixedHeight(settingsTitleLabelNominalHeight);
        ui->tunnelsScrollArea->setFixedHeight(height-settingsTitleLabelNominalHeight-ui->horizontalLayout_42->geometry().height()-2*ui->verticalLayout_4->spacing());
        ui->tunnelsTitleLabel->setFixedHeight(settingsTitleLabelNominalHeight);
    }else{
        ui->verticalLayout_7->invalidate();
        ui->wrongInputLabel->adjustSize();
        ui->stackedWidget->adjustSize();
        ui->stackedWidget->setFixedHeight(HEIGHT);
        ui->settingsPage->setFixedHeight(HEIGHT);
        ui->verticalLayoutWidget_4->setGeometry(QRect(0, 0, WIDTH, HEIGHT));
        ui->stackedWidget->setFixedHeight(HEIGHT);
        ui->settingsScrollArea->setFixedHeight(HEIGHT-settingsTitleLabelNominalHeight-ui->verticalLayout_4->spacing());
        ui->settingsTitleLabel->setFixedHeight(settingsTitleLabelNominalHeight);
        ui->tunnelsScrollArea->setFixedHeight(HEIGHT-settingsTitleLabelNominalHeight-ui->horizontalLayout_42->geometry().height()-2*ui->verticalLayout_4->spacing());
        ui->tunnelsTitleLabel->setFixedHeight(settingsTitleLabelNominalHeight);
    }
}

void MainWindow::highlightWrongInput(QString warningText, WrongInputPageEnum inputPage, QWidget* widgetToFocus) {
    bool redVisible = ui->wrongInputLabel->isVisible();
    ui->wrongInputLabel->setVisible(true);
    ui->wrongInputLabel->setText(warningText);
    if(!redVisible)adjustSizesAccordingToWrongLabel();
    if(widgetToFocus){ui->settingsScrollArea->ensureWidgetVisible(widgetToFocus);widgetToFocus->setFocus();}
    switch(inputPage) {
        case WrongInputPageEnum::generalSettingsPage: showSettingsPage(); break;
        case WrongInputPageEnum::tunnelsSettingsPage: showTunnelsPage(); break;
        default: assert(false); break;
    }
}

void MainWindow::syncLogLevel (int /*comboBoxIndex*/) {
    std::string level = uiSettings->logLevelComboBox->currentText().toLower().toStdString();
    if (level == "none" || level == "error" || level == "warn" || level == "info" || level == "debug")
        i2p::log::Logger().SetLogLevel(level);
    else {
        LogPrint(eLogError, "unknown loglevel set attempted");
        return;
    }
    i2p::log::Logger().Reopen ();
}

