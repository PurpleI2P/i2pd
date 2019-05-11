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
class DNCPParameters;

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

    //dncp

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
    dotnet::data::SigningKeyType readSigTypeComboboxUI(QComboBox* sigTypeComboBox);

public:
    //returns false when invalid data at UI
    virtual bool applyDataFromUIToTunnelConfig() {
        tunnelConfig->setName(nameLineEdit->text().toStdString());
        tunnelConfig->setType(readTunnelTypeComboboxData());
        DNCPParameters& dncpParams=tunnelConfig->getI2cpParameters();
        dncpParams.setInbound_length(inbound_lengthLineEdit->text());
        dncpParams.setInbound_quantity(inbound_quantityLineEdit->text());
        dncpParams.setOutbound_length(outbound_lengthLineEdit->text());
        dncpParams.setOutbound_quantity(outbound_quantityLineEdit->text());
        dncpParams.setCrypto_tagsToSend(crypto_tagsToSendLineEdit->text());
        return true;
    }
protected:
    void setupTunnelPane(
            TunnelConfig* tunnelConfig,
            QGroupBox *tunnelGroupBox,
            QWidget* gridLayoutWidget_2, QComboBox * tunnelTypeComboBox,
            QWidget *tunnelsFormGridLayoutWidget, int tunnelsRow, int height, int h);
    void appendControlsForDNCPParameters(DNCPParameters& dncpParameters, int& gridIndex);
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

    void retranslateDNCPParameters() {
        inbound_lengthLabel->setText(QApplication::translate("tunForm", "Number of hops of an inbound tunnel:", 0));;
        outbound_lengthLabel->setText(QApplication::translate("tunForm", "Number of hops of an outbound tunnel:", 0));;
        inbound_quantityLabel->setText(QApplication::translate("tunForm", "Number of inbound tunnels:", 0));;
        outbound_quantityLabel->setText(QApplication::translate("tunForm", "Number of outbound tunnels:", 0));;
        crypto_tagsToSendLabel->setText(QApplication::translate("tunForm", "Number of ElGamal/AES tags to send:", 0));;
    }
};

#endif // TUNNELPANE_H
