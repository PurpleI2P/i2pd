#ifndef TUNNELPANE_H
#define TUNNELPANE_H

#include "QObject"
#include "QWidget"
#include "QComboBox"
#include "QGridLayout"
#include "QLabel"
#include "QPushButton"
#include "QApplication"
#include "QLineEdit"
#include "QGroupBox"
#include "QVBoxLayout"
#include "QCheckBox"

#include "TunnelConfig.h"

#include <widgetlock.h>
#include <widgetlockregistry.h>

class ServerTunnelPane;
class ClientTunnelPane;

class TunnelConfig;
class I2CPParameters;

class MainWindow;

class TunnelPane : public QObject {

    Q_OBJECT

public:
    TunnelPane(TunnelsPageUpdateListener* tunnelsPageUpdateListener_, TunnelConfig* tunconf, QWidget* wrongInputPane_, QLabel* wrongInputLabel_, MainWindow* mainWindow_);
    virtual ~TunnelPane(){}

    void deleteTunnelForm();

    void hideWrongInputLabel() const;
    void highlightWrongInput(QString warningText, QWidget* controlWithWrongInput);

    virtual ServerTunnelPane* asServerTunnelPane()=0;
    virtual ClientTunnelPane* asClientTunnelPane()=0;

    void deleteWidget();

protected:
    MainWindow* mainWindow;
    QWidget * wrongInputPane;
    QLabel* wrongInputLabel;
    TunnelConfig* tunnelConfig;
    widgetlockregistry widgetlocks;
    TunnelsPageUpdateListener* tunnelsPageUpdateListener;
    QVBoxLayout *tunnelGridLayout;
    QGroupBox *tunnelGroupBox;
    QWidget* gridLayoutWidget_2;

    //header
    QLabel *nameLabel;
    QLineEdit *nameLineEdit;
public:
    QLineEdit * getNameLineEdit() { return nameLineEdit; }

public slots:
    void updated();
    void deleteButtonReleased();

protected:
    QSpacerItem *headerHorizontalSpacer;
    QPushButton *deletePushButton;

    //type
    QComboBox *tunnelTypeComboBox;
    QLabel *typeLabel;

    //i2cp

    QLabel * inbound_lengthLabel;
    QLineEdit * inbound_lengthLineEdit;

    QLabel * outbound_lengthLabel;
    QLineEdit * outbound_lengthLineEdit;

    QLabel * inbound_quantityLabel;
    QLineEdit * inbound_quantityLineEdit;

    QLabel * outbound_quantityLabel;
    QLineEdit * outbound_quantityLineEdit;

    QLabel * crypto_tagsToSendLabel;
    QLineEdit * crypto_tagsToSendLineEdit;

    QLabel * explicitPeersLabel;
    QLineEdit * explicitPeersLineEdit;

    QLabel * i2p_streaming_initialAckDelayLabel;
    QLineEdit * i2p_streaming_initialAckDelayLineEdit;

    QCheckBox * i2p_streaming_answerPingsCheckBox;

    QLabel * i2cp_leaseSetTypeLabel;
    QLineEdit * i2cp_leaseSetTypeLineEdit;

    QLabel * i2cp_leaseSetEncTypeLabel;
    QLineEdit * i2cp_leaseSetEncTypeLineEdit;

    QLabel * i2cp_leaseSetPrivKeyLabel;
    QLineEdit * i2cp_leaseSetPrivKeyLineEdit;

    QLabel * i2cp_leaseSetAuthTypeLabel;
    QLineEdit * i2cp_leaseSetAuthTypeLineEdit;


    QString readTunnelTypeComboboxData();

    //should be created by factory
    i2p::data::SigningKeyType readSigTypeComboboxUI(QComboBox* sigTypeComboBox);

public:
    //returns false when invalid data at UI
    virtual bool applyDataFromUIToTunnelConfig() {
        if(!isValidSingleLine(nameLineEdit)){
            setGroupBoxTitle(QApplication::translate("tunPage", "invalid_tunnel_name"));
            return false;
        }
        if(!isValidSingleLine(inbound_lengthLineEdit))return false;
        if(!isValidSingleLine(inbound_quantityLineEdit))return false;
        if(!isValidSingleLine(outbound_lengthLineEdit))return false;
        if(!isValidSingleLine(outbound_quantityLineEdit))return false;
        if(!isValidSingleLine(crypto_tagsToSendLineEdit))return false;
        if(!isValidSingleLine(i2cp_leaseSetAuthTypeLineEdit))return false;
        if(!isValidSingleLine(i2cp_leaseSetEncTypeLineEdit))return false;
        if(!isValidSingleLine(i2cp_leaseSetPrivKeyLineEdit))return false;
        if(!isValidSingleLine(i2cp_leaseSetTypeLineEdit))return false;
        if(!isValidSingleLine(i2p_streaming_initialAckDelayLineEdit))return false;
        setGroupBoxTitle(nameLineEdit->text());
        tunnelConfig->setName(nameLineEdit->text().toStdString());
        tunnelConfig->setType(readTunnelTypeComboboxData());
        I2CPParameters& i2cpParams=tunnelConfig->getI2cpParameters();
        i2cpParams.setInbound_length(inbound_lengthLineEdit->text());
        i2cpParams.setInbound_quantity(inbound_quantityLineEdit->text());
        i2cpParams.setOutbound_length(outbound_lengthLineEdit->text());
        i2cpParams.setOutbound_quantity(outbound_quantityLineEdit->text());
        i2cpParams.setCrypto_tagsToSend(crypto_tagsToSendLineEdit->text());
        i2cpParams.set_i2cp_leaseSetAuthType(i2cp_leaseSetAuthTypeLineEdit->text());
        i2cpParams.set_i2cp_leaseSetEncType(i2cp_leaseSetEncTypeLineEdit->text());
        i2cpParams.set_i2cp_leaseSetPrivKey(i2cp_leaseSetPrivKeyLineEdit->text());
        i2cpParams.set_i2cp_leaseSetType(i2cp_leaseSetTypeLineEdit->text());
        i2cpParams.set_i2p_streaming_answerPings(i2p_streaming_answerPingsCheckBox->isChecked());
        i2cpParams.set_i2p_streaming_initialAckDelay(i2p_streaming_initialAckDelayLineEdit->text());
        return true;
    }
protected:
    void setupTunnelPane(
            TunnelConfig* tunnelConfig,
            QGroupBox *tunnelGroupBox,
            QWidget* gridLayoutWidget_2, QComboBox * tunnelTypeComboBox,
            QWidget *tunnelsFormGridLayoutWidget, int tunnelsRow, int height, int h);
    void appendControlsForI2CPParameters(I2CPParameters& i2cpParameters, int& gridIndex);
public:
    int height() {
        return gridLayoutWidget_2?gridLayoutWidget_2->height():0;
    }

protected slots:
    virtual void setGroupBoxTitle(const QString & title)=0;
private:
    void retranslateTunnelForm(TunnelPane& ui) {
        ui.deletePushButton->setText(QApplication::translate("tunForm", "Delete Tunnel", 0));
        ui.nameLabel->setText(QApplication::translate("tunForm", "Tunnel name:", 0));
    }

    void retranslateI2CPParameters() {
        inbound_lengthLabel->setText(QApplication::translate("tunForm", "Number of hops of an inbound tunnel:", 0));;
        outbound_lengthLabel->setText(QApplication::translate("tunForm", "Number of hops of an outbound tunnel:", 0));;
        inbound_quantityLabel->setText(QApplication::translate("tunForm", "Number of inbound tunnels:", 0));;
        outbound_quantityLabel->setText(QApplication::translate("tunForm", "Number of outbound tunnels:", 0));;
        crypto_tagsToSendLabel->setText(QApplication::translate("tunForm", "Number of ElGamal/AES tags to send:", 0));;
        explicitPeersLabel->setText(QApplication::translate("tunForm", "List of comma-separated b64 addresses of peers to use:", 0));;
        i2p_streaming_initialAckDelayLabel->setText(QApplication::translate("tunForm", "Milliseconds to wait before sending Ack:", 0));
        i2p_streaming_answerPingsCheckBox->setText(QApplication::translate("tunForm", "Enable sending pongs", 0));
        i2cp_leaseSetTypeLabel->setText(QApplication::translate("tunForm", "Type of LeaseSet to be sent. 1, 3 or 5:", 0));
        i2cp_leaseSetEncTypeLabel->setText(QApplication::translate("tunForm", "Comma-separ. encr. types to be used in LeaseSet type 3 or 5:", 0));
        i2cp_leaseSetPrivKeyLabel->setText(QApplication::translate("tunForm", "Decryption key for encrypted LeaseSet in base64. PSK or private DH:", 0));
        i2cp_leaseSetAuthTypeLabel->setText(QApplication::translate("tunForm", "Auth type for encrypted LeaseSet. 0 - no auth, 1 - DH, 2 - PSK:", 0));
    }
protected:
    bool isValidSingleLine(QLineEdit* widget);
};

#endif // TUNNELPANE_H
