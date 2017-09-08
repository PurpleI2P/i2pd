#ifndef CLIENTTUNNELPANE_H
#define CLIENTTUNNELPANE_H

#include "QGridLayout"
#include "QVBoxLayout"

#include "TunnelPane.h"

class ClientTunnelConfig;

class ServerTunnelPane;
class TunnelPane;

class ClientTunnelPane : public TunnelPane {
    Q_OBJECT
public:
    ClientTunnelPane(TunnelsPageUpdateListener* tunnelsPageUpdateListener, ClientTunnelConfig* tunconf, QWidget* wrongInputPane_, QLabel* wrongInputLabel_, MainWindow* mainWindow);
    virtual ~ClientTunnelPane(){}
    virtual ServerTunnelPane* asServerTunnelPane();
    virtual ClientTunnelPane* asClientTunnelPane();
    int appendClientTunnelForm(ClientTunnelConfig* tunnelConfig, QWidget *tunnelsFormGridLayoutWidget,
                                int tunnelsRow, int height);
    void deleteClientTunnelForm();
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
protected:
    virtual bool applyDataFromUIToTunnelConfig() {
        QString cannotSaveSettings = QApplication::tr("Cannot save settings.");
        bool ok=TunnelPane::applyDataFromUIToTunnelConfig();
        if(!ok)return false;
        ClientTunnelConfig* ctc=tunnelConfig->asClientTunnelConfig();
        assert(ctc!=nullptr);

        //destination
        ctc->setdest(destinationLineEdit->text().toStdString());

        auto portStr=portLineEdit->text();
        int portInt=portStr.toInt(&ok);

        if(!ok){
            highlightWrongInput(QApplication::tr("Bad port, must be int.")+" "+cannotSaveSettings,portLineEdit);
            return false;
        }
        ctc->setport(portInt);

        ctc->setkeys(keysLineEdit->text().toStdString());

        ctc->setaddress(addressLineEdit->text().toStdString());

        auto dportStr=destinationPortLineEdit->text();
        int dportInt=dportStr.toInt(&ok);
        if(!ok){
            highlightWrongInput(QApplication::tr("Bad destinationPort, must be int.")+" "+cannotSaveSettings,destinationPortLineEdit);
            return false;
        }
        ctc->setdestinationPort(dportInt);

        ctc->setsigType(readSigTypeComboboxUI(sigTypeComboBox));
        return true;
    }
};

#endif // CLIENTTUNNELPANE_H
