#include "TunnelPane.h"

TunnelPane::TunnelPane(): QObject(),gridLayoutWidget_2(nullptr) {
}

void TunnelPane::setupTunnelPane(
        TunnelConfig* tunnelConfig,
        QGroupBox *tunnelGroupBox,
        QWidget* gridLayoutWidget_2, QComboBox * tunnelTypeComboBox,
        QWidget *tunnelsFormGridLayoutWidget, QGridLayout *tunnelsFormGridLayout, int tunnelsRow) {
    tunnelsFormGridLayoutWidget->resize(527, tunnelsFormGridLayoutWidget->height()+gridLayoutWidget_2->height());
    tunnelGroupBox->resize(gridLayoutWidget_2->width(), gridLayoutWidget_2->height());
    tunnelsFormGridLayout->addWidget(tunnelGroupBox, tunnelsRow, 0);


    this->tunnelGroupBox=tunnelGroupBox;

    gridLayoutWidget_2->setObjectName(QStringLiteral("gridLayoutWidget_2"));
    this->gridLayoutWidget_2=gridLayoutWidget_2;
    tunnelGridLayout = new QGridLayout(gridLayoutWidget_2);
    tunnelGridLayout->setObjectName(QStringLiteral("tunnelGridLayout"));
    tunnelGridLayout->setContentsMargins(5, 5, 5, 5);
    tunnelGridLayout->setVerticalSpacing(5);

    //header
    QHBoxLayout *headerHorizontalLayout = new QHBoxLayout();
    headerHorizontalLayout->setObjectName(QStringLiteral("headerHorizontalLayout"));

    nameLabel = new QLabel(gridLayoutWidget_2);
    nameLabel->setObjectName(QStringLiteral("nameLabel"));
    headerHorizontalLayout->addWidget(nameLabel);
    nameLineEdit = new QLineEdit(gridLayoutWidget_2);
    nameLineEdit->setObjectName(QStringLiteral("nameLineEdit"));
    const QString& tunnelName=tunnelConfig->getName().c_str();
    nameLineEdit->setText(tunnelName);
    setGroupBoxTitle(tunnelName);

    QObject::connect(nameLineEdit, SIGNAL(textChanged(const QString &)),
                             this, SLOT(setGroupBoxTitle(const QString &)));

    headerHorizontalLayout->addWidget(nameLineEdit);
    headerHorizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    headerHorizontalLayout->addItem(headerHorizontalSpacer);
    deletePushButton = new QPushButton(gridLayoutWidget_2);//TODO handle it
    deletePushButton->setObjectName(QStringLiteral("deletePushButton"));
    headerHorizontalLayout->addWidget(deletePushButton);
    tunnelGridLayout->addLayout(headerHorizontalLayout, 0, 0, 1, 1);

    //type
    {
        const QString& type = tunnelConfig->getType();
        QHBoxLayout * horizontalLayout_ = new QHBoxLayout();
        horizontalLayout_->setObjectName(QStringLiteral("horizontalLayout_"));
        typeLabel = new QLabel(gridLayoutWidget_2);
        typeLabel->setObjectName(QStringLiteral("typeLabel"));
        horizontalLayout_->addWidget(typeLabel);
        horizontalLayout_->addWidget(tunnelTypeComboBox);
        this->tunnelTypeComboBox=tunnelTypeComboBox;
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_, 1, 0, 1, 1);
    }

    retranslateTunnelForm(*this);
}

void TunnelPane::appendControlsForI2CPParameters(I2CPParameters& i2cpParameters, int& gridIndex) {
    {
        //number of hops of an inbound tunnel
        const QString& inbound_length=i2cpParameters.getInbound_length();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        inbound_lengthLabel = new QLabel(gridLayoutWidget_2);
        inbound_lengthLabel->setObjectName(QStringLiteral("inbound_lengthLabel"));
        horizontalLayout_2->addWidget(inbound_lengthLabel);
        inbound_lengthLineEdit = new QLineEdit(gridLayoutWidget_2);
        inbound_lengthLineEdit->setObjectName(QStringLiteral("inbound_lengthLineEdit"));
        inbound_lengthLineEdit->setText(inbound_length);
        inbound_lengthLineEdit->setMaximumWidth(80);
        horizontalLayout_2->addWidget(inbound_lengthLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2, ++gridIndex, 0, 1, 1);
    }
    {
        //number of hops of an outbound tunnel
        const QString& outbound_length=i2cpParameters.getOutbound_length();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        outbound_lengthLabel = new QLabel(gridLayoutWidget_2);
        outbound_lengthLabel->setObjectName(QStringLiteral("outbound_lengthLabel"));
        horizontalLayout_2->addWidget(outbound_lengthLabel);
        outbound_lengthLineEdit = new QLineEdit(gridLayoutWidget_2);
        outbound_lengthLineEdit->setObjectName(QStringLiteral("outbound_lengthLineEdit"));
        outbound_lengthLineEdit->setText(outbound_length);
        outbound_lengthLineEdit->setMaximumWidth(80);
        horizontalLayout_2->addWidget(outbound_lengthLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2, ++gridIndex, 0, 1, 1);
    }
    {
        //number of inbound tunnels
        const QString& inbound_quantity=i2cpParameters.getInbound_quantity();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        inbound_quantityLabel = new QLabel(gridLayoutWidget_2);
        inbound_quantityLabel->setObjectName(QStringLiteral("inbound_quantityLabel"));
        horizontalLayout_2->addWidget(inbound_quantityLabel);
        inbound_quantityLineEdit = new QLineEdit(gridLayoutWidget_2);
        inbound_quantityLineEdit->setObjectName(QStringLiteral("inbound_quantityLineEdit"));
        inbound_quantityLineEdit->setText(inbound_quantity);
        inbound_quantityLineEdit->setMaximumWidth(80);
        horizontalLayout_2->addWidget(inbound_quantityLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2, ++gridIndex, 0, 1, 1);
    }
    {
        //number of outbound tunnels
        const QString& outbound_quantity=i2cpParameters.getOutbound_quantity();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        outbound_quantityLabel = new QLabel(gridLayoutWidget_2);
        outbound_quantityLabel->setObjectName(QStringLiteral("outbound_quantityLabel"));
        horizontalLayout_2->addWidget(outbound_quantityLabel);
        outbound_quantityLineEdit = new QLineEdit(gridLayoutWidget_2);
        outbound_quantityLineEdit->setObjectName(QStringLiteral("outbound_quantityLineEdit"));
        outbound_quantityLineEdit->setText(outbound_quantity);
        outbound_quantityLineEdit->setMaximumWidth(80);
        horizontalLayout_2->addWidget(outbound_quantityLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2, ++gridIndex, 0, 1, 1);
    }
    {
        //number of ElGamal/AES tags to send
        const QString& crypto_tagsToSend=i2cpParameters.getCrypto_tagsToSend();
        QHBoxLayout *horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        crypto_tagsToSendLabel = new QLabel(gridLayoutWidget_2);
        crypto_tagsToSendLabel->setObjectName(QStringLiteral("crypto_tagsToSendLabel"));
        horizontalLayout_2->addWidget(crypto_tagsToSendLabel);
        crypto_tagsToSendLineEdit = new QLineEdit(gridLayoutWidget_2);
        crypto_tagsToSendLineEdit->setObjectName(QStringLiteral("crypto_tagsToSendLineEdit"));
        crypto_tagsToSendLineEdit->setText(crypto_tagsToSend);
        crypto_tagsToSendLineEdit->setMaximumWidth(80);
        horizontalLayout_2->addWidget(crypto_tagsToSendLineEdit);
        QSpacerItem * horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
        horizontalLayout_2->addItem(horizontalSpacer);
        tunnelGridLayout->addLayout(horizontalLayout_2, ++gridIndex, 0, 1, 1);
    }

    retranslateI2CPParameters();
}
