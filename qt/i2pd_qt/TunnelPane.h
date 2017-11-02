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

    QString readTunnelTypeComboboxData();

    //should be created by factory
    i2p::data::SigningKeyType readSigTypeComboboxUI(QComboBox* sigTypeComboBox);

public:
    //returns false when invalid data at UI
    virtual bool applyDataFromUIToTunnelConfig() {
        tunnelConfig->setName(nameLineEdit->text().toStdString());
        tunnelConfig->setType(readTunnelTypeComboboxData());
        I2CPParameters& i2cpParams=tunnelConfig->getI2cpParameters();
        i2cpParams.setInbound_length(inbound_lengthLineEdit->text());
        i2cpParams.setInbound_quantity(inbound_quantityLineEdit->text());
        i2cpParams.setOutbound_length(outbound_lengthLineEdit->text());
        i2cpParams.setOutbound_quantity(outbound_quantityLineEdit->text());
        i2cpParams.setCrypto_tagsToSend(crypto_tagsToSendLineEdit->text());
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
    }
};

#endif // TUNNELPANE_H
