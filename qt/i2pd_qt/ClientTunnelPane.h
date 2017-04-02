#ifndef CLIENTTUNNELPANE_H
#define CLIENTTUNNELPANE_H

#include "QGridLayout"

#include "TunnelPane.h"

class ClientTunnelConfig;

class ServerTunnelPane;
class TunnelPane;

class ClientTunnelPane : public TunnelPane {
    Q_OBJECT
public:
    ClientTunnelPane();
    virtual ~ClientTunnelPane(){}
    virtual ServerTunnelPane* asServerTunnelPane();
    virtual ClientTunnelPane* asClientTunnelPane();
    void appendClientTunnelForm(ClientTunnelConfig* tunnelConfig, QWidget *tunnelsFormGridLayoutWidget,
                                QGridLayout *tunnelsFormGridLayout, int tunnelsRow);
    void deleteClientTunnelForm(QGridLayout *tunnelsFormGridLayout);
private:
    QGroupBox *clientTunnelNameGroupBox;

    //tunnel
    QWidget *gridLayoutWidget_2;

    //destination
    QHBoxLayout *horizontalLayout_2;
    QLabel *destinationLabel;
    QLineEdit *destinationLineEdit;
    QSpacerItem *destinationHorizontalSpacer;

    //port
    QLabel * portLabel;
    QLineEdit * portLineEdit;

    //keys
    QLabel * keysLabel;
    QLineEdit * keysLineEdit;

    //address
    QLabel * addressLabel;
    QLineEdit * addressLineEdit;

    //destinationPort
    QLabel * destinationPortLabel;
    QLineEdit * destinationPortLineEdit;

protected slots:
    virtual void setGroupBoxTitle(const QString & title);

private:
    void retranslateClientTunnelForm(ClientTunnelPane& /*ui*/) {
        destinationLabel->setText(QApplication::translate("srvTunForm", "Destination:", 0));
        portLabel->setText(QApplication::translate("srvTunForm", "Port:", 0));
        keysLabel->setText(QApplication::translate("srvTunForm", "Keys:", 0));
        destinationPortLabel->setText(QApplication::translate("srvTunForm", "Destination port:", 0));
        addressLabel->setText(QApplication::translate("srvTunForm", "Address:", 0));
    }

};

#endif // CLIENTTUNNELPANE_H
