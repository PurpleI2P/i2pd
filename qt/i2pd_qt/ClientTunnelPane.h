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

    //sigType
    QLabel * sigTypeLabel;
    QComboBox * sigTypeComboBox;

protected slots:
    virtual void setGroupBoxTitle(const QString & title);

private:
    void retranslateClientTunnelForm(ClientTunnelPane& /*ui*/) {
        typeLabel->setText(QApplication::translate("cltTunForm", "Client tunnel type:", 0));
        destinationLabel->setText(QApplication::translate("cltTunForm", "Destination:", 0));
        portLabel->setText(QApplication::translate("cltTunForm", "Port:", 0));
        keysLabel->setText(QApplication::translate("cltTunForm", "Keys:", 0));
        destinationPortLabel->setText(QApplication::translate("cltTunForm", "Destination port:", 0));
        addressLabel->setText(QApplication::translate("cltTunForm", "Address:", 0));
        sigTypeLabel->setText(QApplication::translate("cltTunForm", "Signature type:", 0));
    }

};

#endif // CLIENTTUNNELPANE_H
