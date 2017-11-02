#include "ClientTunnelPane.h"
#include "ClientContext.h"
#include "SignatureTypeComboboxFactory.h"
#include "QVBoxLayout"

ClientTunnelPane::ClientTunnelPane(TunnelsPageUpdateListener* tunnelsPageUpdateListener, ClientTunnelConfig* tunconf, QWidget* wrongInputPane_, QLabel* wrongInputLabel_, MainWindow* mainWindow):
    TunnelPane(tunnelsPageUpdateListener, tunconf, wrongInputPane_, wrongInputLabel_, mainWindow) {}

void ClientTunnelPane::setGroupBoxTitle(const QString & title) {
    clientTunnelNameGroupBox->setTitle(title);
}

void ClientTunnelPane::deleteClientTunnelForm() {
    TunnelPane::deleteTunnelForm();
    delete clientTunnelNameGroupBox;
    clientTunnelNameGroupBox=nullptr;

    //gridLayoutWidget_2->deleteLater();
    //gridLayoutWidget_2=nullptr;
}

int ClientTunnelPane::appendClientTunnelForm(
        ClientTunnelConfig* tunnelConfig, QWidget *tunnelsFormGridLayoutWidget, int tunnelsRow, int height) {

    ClientTunnelPane& ui = *this;

    clientTunnelNameGroupBox = new QGroupBox(tunnelsFormGridLayoutWidget);
    clientTunnelNameGroupBox->setObjectName(QStringLiteral("clientTunnelNameGroupBox"));

    //tunnel
    gridLayoutWidget_2 = new QWidget(clientTunnelNameGroupBox);

    QComboBox *tunnelTypeComboBox = new QComboBox(gridLayoutWidget_2);
    tunnelTypeComboBox->setObjectName(QStringLiteral("tunnelTypeComboBox"));
    tunnelTypeComboBox->addItem("Client", i2p::client::I2P_TUNNELS_SECTION_TYPE_CLIENT);
    tunnelTypeComboBox->addItem("Socks", i2p::client::I2P_TUNNELS_SECTION_TYPE_SOCKS);
    tunnelTypeComboBox->addItem("Websocks", i2p::client::I2P_TUNNELS_SECTION_TYPE_WEBSOCKS);
    tunnelTypeComboBox->addItem("HTTP Proxy", i2p::client::I2P_TUNNELS_SECTION_TYPE_HTTPPROXY);
    tunnelTypeComboBox->addItem("UDP Client", i2p::client::I2P_TUNNELS_SECTION_TYPE_UDPCLIENT);

    int h=(7+4)*60;
    gridLayoutWidget_2->setGeometry(QRect(0, 0, 561, h));
    clientTunnelNameGroupBox->setGeometry(QRect(0, 0, 561, h));

    {
        const QString& type = tunnelConfig->getType();
        int index=0;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_CLIENT)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_SOCKS)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_WEBSOCKS)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_HTTPPROXY)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
        if(type==i2p::client::I2P_TUNNELS_SECTION_TYPE_UDPCLIENT)tunnelTypeComboBox->setCurrentIndex(index);
        ++index;
    }

    setupTunnelPane(tunnelConfig,
                    clientTunnelNameGroupBox,
                    gridLayoutWidget_2, tunnelTypeComboBox,
                    tunnelsFormGridLayoutWidget, tunnelsRow, height, h);
    //this->tunnelGroupBox->setGeometry(QRect(0, tunnelsFormGridLayoutWidget->height()+10, 561, (7+5)*40+10));

    /*
        std::string destination;
    */

    //host
    ui.horizontalLayout_2 = new QHBoxLayout();
    horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
    ui.destinationLabel = new QLabel(gridLayoutWidget_2);
    destinationLabel->setObjectName(QStringLiteral("destinationLabel"));
    horizontalLayout_2->addWidget(destinationLabel);
    ui.destinationLineEdit = new QLineEdit(gridLayoutWidget_2);
    destinationLineEdit->setObjectName(QStringLiteral("destinationLineEdit"));
    destinationLineEdit->setText(tunnelConfig->getdest().c_str());
    QObject::connect(destinationLineEdit, SIGNAL(textChanged(const QString &)),
                             this, SLOT(updated()));
    horizontalLayout_2->addWidget(destinationLineEdit);
    ui.destinationHorizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    horizontalLayout_2->addItem(destinationHorizontalSpacer);
    tunnelGridLayout->addLayout(horizontalLayout_2);

 /*
  *        int port;
 */
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
    /*
     *         std::string keys;
*/
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
    /*
     *         std::string address;
     */
    {
        std::string address  = tunnelConfig->getaddress();
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

    /*
        int destinationPort;
        i2p::data::SigningKeyType sigType;
*/
    {
        int destinationPort = tunnelConfig->getdestinationPort();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        ui.destinationPortLabel = new QLabel(gridLayoutWidget_2);
        destinationPortLabel->setObjectName(QStringLiteral("destinationPortLabel"));
        horizontalLayout_2->addWidget(destinationPortLabel);
        ui.destinationPortLineEdit = new QLineEdit(gridLayoutWidget_2);
        destinationPortLineEdit->setObjectName(QStringLiteral("destinationPortLineEdit"));
        destinationPortLineEdit->setText(QString::number(destinationPort));
        destinationPortLineEdit->setMaximumWidth(80);
        QObject::connect(destinationPortLineEdit, SIGNAL(textChanged(const QString &)),
                                 this, SLOT(updated()));
        horizontalLayout_2->addWidget(destinationPortLineEdit);
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
        I2CPParameters& i2cpParameters = tunnelConfig->getI2cpParameters();
        appendControlsForI2CPParameters(i2cpParameters, gridIndex);
    }

    retranslateClientTunnelForm(ui);

    tunnelGridLayout->invalidate();

    return h;
}

ServerTunnelPane* ClientTunnelPane::asServerTunnelPane(){return nullptr;}
ClientTunnelPane* ClientTunnelPane::asClientTunnelPane(){return this;}
