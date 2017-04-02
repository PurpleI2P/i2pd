#ifndef SERVERTUNNELPANE_H
#define SERVERTUNNELPANE_H

#include "TunnelPane.h"
#include "mainwindow.h"

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QWidget>

class ServerTunnelConfig;

class ClientTunnelPane;

class ServerTunnelPane : public TunnelPane {
    Q_OBJECT

public:
    ServerTunnelPane();
    virtual ~ServerTunnelPane(){}

    virtual ServerTunnelPane* asServerTunnelPane();
    virtual ClientTunnelPane* asClientTunnelPane();

    void appendServerTunnelForm(ServerTunnelConfig* tunnelConfig, QWidget *tunnelsFormGridLayoutWidget,
                                QGridLayout *tunnelsFormGridLayout, int tunnelsRow);
    void deleteServerTunnelForm(QGridLayout *tunnelsFormGridLayout);

private:
    QGroupBox *serverTunnelNameGroupBox;

    //tunnel
    QWidget *gridLayoutWidget_2;

    //host
    QHBoxLayout *horizontalLayout_2;
    QLabel *hostLabel;
    QLineEdit *hostLineEdit;
    QSpacerItem *hostHorizontalSpacer;

    //port
    QLabel * portLabel;
    QLineEdit * portLineEdit;

    //keys
    QLabel * keysLabel;
    QLineEdit * keysLineEdit;

    //inPort
    QLabel * inPortLabel;
    QLineEdit * inPortLineEdit;

    //accessList
    QLabel * accessListLabel;
    QLineEdit * accessListLineEdit;

    //hostOverride
    QLabel * hostOverrideLabel;
    QLineEdit * hostOverrideLineEdit;

    //webIRCPass
    QLabel * webIRCPassLabel;
    QLineEdit * webIRCPassLineEdit;

    //address
    QLabel * addressLabel;
    QLineEdit * addressLineEdit;

    //maxConns
    QLabel * maxConnsLabel;
    QLineEdit * maxConnsLineEdit;

    //gzip
    QCheckBox * gzipCheckBox;

    //isUniqueLocal
    QCheckBox * isUniqueLocalCheckBox;

protected slots:
    virtual void setGroupBoxTitle(const QString & title);

private:
    void retranslateServerTunnelForm(ServerTunnelPane& /*ui*/) {
        hostLabel->setText(QApplication::translate("srvTunForm", "Host:", 0));
        portLabel->setText(QApplication::translate("srvTunForm", "Port:", 0));
        keysLabel->setText(QApplication::translate("srvTunForm", "Keys:", 0));
        inPortLabel->setText(QApplication::translate("srvTunForm", "InPort:", 0));
        accessListLabel->setText(QApplication::translate("srvTunForm", "Access list:", 0));
        hostOverrideLabel->setText(QApplication::translate("srvTunForm", "Host override:", 0));
        webIRCPassLabel->setText(QApplication::translate("srvTunForm", "WebIRC password:", 0));
        addressLabel->setText(QApplication::translate("srvTunForm", "Address:", 0));
        maxConnsLabel->setText(QApplication::translate("srvTunForm", "Max connections:", 0));

        gzipCheckBox->setText(QApplication::translate("srvTunForm", "GZip", 0));
        isUniqueLocalCheckBox->setText(QApplication::translate("srvTunForm", "Is unique local", 0));
    }

};

#endif // SERVERTUNNELPANE_H
