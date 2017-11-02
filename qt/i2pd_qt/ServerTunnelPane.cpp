#include "ServerTunnelPane.h"
#include "ClientContext.h"
#include "SignatureTypeComboboxFactory.h"

ServerTunnelPane::ServerTunnelPane(TunnelsPageUpdateListener* tunnelsPageUpdateListener, ServerTunnelConfig* tunconf, QWidget* wrongInputPane_, QLabel* wrongInputLabel_, MainWindow* mainWindow):
    TunnelPane(tunnelsPageUpdateListener, tunconf, wrongInputPane_, wrongInputLabel_, mainWindow) {}

void ServerTunnelPane::setGroupBoxTitle(const QString & title) {
    serverTunnelNameGroupBox->setTitle(title);
}

int ServerTunnelPane::appendServerTunnelForm(
        ServerTunnelConfig* tunnelConfig, QWidget *tunnelsFormGridLayoutWidget, int tunnelsRow, int height) {

    ServerTunnelPane& ui = *this;

    serverTunnelNameGroupBox = new QGroupBox(tunnelsFormGridLayoutWidget);
    serverTunnelNameGroupBox->setObjectName(QStringLiteral("serverTunnelNameGroupBox"));

    //tunnel
    gridLayoutWidget_2 = new QWidget(serverTunnelNameGroupBox);

    QComboBox *tunnelTypeComboBox = new QComboBox(gridLayoutWidget_2);
    tunnelTypeComboBox->setObjectName(QStringLiteral("tunnelTypeComboBox"));
    tunnelTypeComboBox->addItem("Server", i2p::client::I2P_TUNNELS_SECTION_TYPE_SERVER);
    tunnelTypeComboBox->addItem("HTTP", i2p::client::I2P_TUNNELS_SECTION_TYPE_HTTP);
    tunnelTypeComboBox->addItem("IRC", i2p::client::I2P_TUNNELS_SECTION_TYPE_IRC);
    tunnelTypeComboBox->addItem("UDP Server", i2p::client::I2P_TUNNELS_SECTION_TYPE_UDPSERVER);

    int h=19*60;
    gridLayoutWidget_2->setGeometry(QRect(0, 0, 561, h));
    serverTunnelNameGroupBox->setGeometry(QRect(0, 0, 561, h));

    {
        const QString& type = tunnelConfig->getType();
        int index=0;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_SERVER)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_HTTP)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_IRC)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_UDPSERVER)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
    }

    setupTunnelPane(tunnelConfig,
                    serverTunnelNameGroupBox,
                    gridLayoutWidget_2, tunnelTypeComboBox,
                    tunnelsFormGridLayoutWidget, tunnelsRow, height, h);
    //this->tunnelGroupBox->setGeometry(QRect(0, tunnelsFormGridLayoutWidget->height()+10, 561, 18*40+10));

    //host
    ui.horizontalLayout_2 = new QHBoxLayout();
    horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
    ui.hostLabel = new QLabel(gridLayoutWidget_2);
    hostLabel->setObjectName(QStringLiteral("hostLabel"));
    horizontalLayout_2->addWidget(hostLabel);
    ui.hostLineEdit = new QLineEdit(gridLayoutWidget_2);
    hostLineEdit->setObjectName(QStringLiteral("hostLineEdit"));
    hostLineEdit->setText(tunnelConfig->gethost().c_str());
    QObject::connect(hostLineEdit, SIGNAL(textChanged(const QString &)),
                             this, SLOT(updated()));
    horizontalLayout_2->addWidget(hostLineEdit);
    ui.hostHorizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    horizontalLayout_2->addItem(hostHorizontalSpacer);
    tunnelGridLayout->addLayout(horizontalLayout_2);

    int gridIndex = 2;
    {
        int port  = tunnelConfig->getport();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.portLabel = new QLabel(gridLayoutWidget_2);
        portLabel->setObjectName(QStringLiteral("portLabel"));
        horizontalLayout_2->addWidget(portLabel);
        ui.portLineEdit = new QLineEdit(gridLayoutWidget_2);
        portLineEdit->setObjectName(QStringLiteral("portLineEdit"));
        portLineEdit->setText(QString::number(port));
        portLineEdit->setMaximumWidth(80);
        QObject::connect(portLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(portLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        std::string keys  = tunnelConfig->getkeys();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.keysLabel = new QLabel(gridLayoutWidget_2);
        keysLabel->setObjectName(QStringLiteral("keysLabel"));
        horizontalLayout_2->addWidget(keysLabel);
        ui.keysLineEdit = new QLineEdit(gridLayoutWidget_2);
        keysLineEdit->setObjectName(QStringLiteral("keysLineEdit"));
        keysLineEdit->setText(keys.c_str());
        QObject::connect(keysLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(keysLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        int inPort = tunnelConfig->getinPort();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.inPortLabel = new QLabel(gridLayoutWidget_2);
        inPortLabel->setObjectName(QStringLiteral("inPortLabel"));
        horizontalLayout_2->addWidget(inPortLabel);
        ui.inPortLineEdit = new QLineEdit(gridLayoutWidget_2);
        inPortLineEdit->setObjectName(QStringLiteral("inPortLineEdit"));
        inPortLineEdit->setText(QString::number(inPort));
        inPortLineEdit->setMaximumWidth(80);
        QObject::connect(inPortLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(inPortLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        std::string accessList = tunnelConfig->getaccessList();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.accessListLabel = new QLabel(gridLayoutWidget_2);
        accessListLabel->setObjectName(QStringLiteral("accessListLabel"));
        horizontalLayout_2->addWidget(accessListLabel);
        ui.accessListLineEdit = new QLineEdit(gridLayoutWidget_2);
        accessListLineEdit->setObjectName(QStringLiteral("accessListLineEdit"));
        accessListLineEdit->setText(accessList.c_str());
        QObject::connect(accessListLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(accessListLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        std::string hostOverride = tunnelConfig->gethostOverride();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.hostOverrideLabel = new QLabel(gridLayoutWidget_2);
        hostOverrideLabel->setObjectName(QStringLiteral("hostOverrideLabel"));
        horizontalLayout_2->addWidget(hostOverrideLabel);
        ui.hostOverrideLineEdit = new QLineEdit(gridLayoutWidget_2);
        hostOverrideLineEdit->setObjectName(QStringLiteral("hostOverrideLineEdit"));
        hostOverrideLineEdit->setText(hostOverride.c_str());
        QObject::connect(hostOverrideLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(hostOverrideLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        std::string webIRCPass = tunnelConfig->getwebircpass();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.webIRCPassLabel = new QLabel(gridLayoutWidget_2);
        webIRCPassLabel->setObjectName(QStringLiteral("webIRCPassLabel"));
        horizontalLayout_2->addWidget(webIRCPassLabel);
        ui.webIRCPassLineEdit = new QLineEdit(gridLayoutWidget_2);
        webIRCPassLineEdit->setObjectName(QStringLiteral("webIRCPassLineEdit"));
        webIRCPassLineEdit->setText(webIRCPass.c_str());
        QObject::connect(webIRCPassLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(webIRCPassLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        bool gzip = tunnelConfig->getgzip();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.gzipCheckBox = new QCheckBox(gridLayoutWidget_2);
        gzipCheckBox->setObjectName(QStringLiteral("gzipCheckBox"));
        gzipCheckBox->setChecked(gzip);
        QObject::connect(gzipCheckBox, SIGNAL(stateChanged(int)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(gzipCheckBox);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        i2p::data::SigningKeyType sigType = tunnelConfig->getsigType();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.sigTypeLabel = new QLabel(gridLayoutWidget_2);
        sigTypeLabel->setObjectName(QStringLiteral("sigTypeLabel"));
        horizontalLayout_2->addWidget(sigTypeLabel);
        ui.sigTypeComboBox = SignatureTypeComboBoxFactory::createSignatureTypeComboBox(gridLayoutWidget_2, sigType);
        sigTypeComboBox->setObjectName(QStringLiteral("sigTypeComboBox"));
        QObject::connect(sigTypeComboBox, SIGNAL(currentIndexChanged(int)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(sigTypeComboBox);
        QPushButton * lockButton2 = new QPushButton(gridLayoutWidget_2);
        horizontalLayout_2->addWidget(lockButton2);
        widgetlocks.add(new widgetlock(sigTypeComboBox, lockButton2));
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        uint32_t maxConns = tunnelConfig->getmaxConns();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.maxConnsLabel = new QLabel(gridLayoutWidget_2);
        maxConnsLabel->setObjectName(QStringLiteral("maxConnsLabel"));
        horizontalLayout_2->addWidget(maxConnsLabel);
        ui.maxConnsLineEdit = new QLineEdit(gridLayoutWidget_2);
        maxConnsLineEdit->setObjectName(QStringLiteral("maxConnsLineEdit"));
        maxConnsLineEdit->setText(QString::number(maxConns));
        maxConnsLineEdit->setMaximumWidth(80);
        QObject::connect(maxConnsLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(maxConnsLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        std::string address = tunnelConfig->getaddress();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.addressLabel = new QLabel(gridLayoutWidget_2);
        addressLabel->setObjectName(QStringLiteral("addressLabel"));
        horizontalLayout_2->addWidget(addressLabel);
        ui.addressLineEdit = new QLineEdit(gridLayoutWidget_2);
        addressLineEdit->setObjectName(QStringLiteral("addressLineEdit"));
        addressLineEdit->setText(address.c_str());
        QObject::connect(addressLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(addressLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        bool isUniqueLocal = tunnelConfig->getisUniqueLocal();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.isUniqueLocalCheckBox = new QCheckBox(gridLayoutWidget_2);
        isUniqueLocalCheckBox->setObjectName(QStringLiteral("isUniqueLocalCheckBox"));
        isUniqueLocalCheckBox->setChecked(isUniqueLocal);
        QObject::connect(gzipCheckBox, SIGNAL(stateChanged(int)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(isUniqueLocalCheckBox);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2);
    }
    {
        I2CPParameters& i2cpParameters = tunnelConfig->getI2cpParameters();
        appendControlsForI2CPParameters(i2cpParameters, gridIndex);
    }

    retranslateServerTunnelForm(ui);

    tunnelGridLayout->invalidate();

    return h;
}

void ServerTunnelPane::deleteServerTunnelForm() {
    TunnelPane::deleteTunnelForm();
    delete serverTunnelNameGroupBox;//->deleteLater();
    serverTunnelNameGroupBox=nullptr;

    //gridLayoutWidget_2->deleteLater();
    //gridLayoutWidget_2=nullptr;
}


ServerTunnelPane* ServerTunnelPane::asServerTunnelPane(){return this;}
ClientTunnelPane* ServerTunnelPane::asClientTunnelPane(){return nullptr;}
