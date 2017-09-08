#ifndef SERVERTUNNELPANE_H
#define SERVERTUNNELPANE_H

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
#include "QVBoxLayout"
#include "QCheckBox"

#include "assert.h"

#include "TunnelPane.h"
#include "TunnelsPageUpdateListener.h"

class ServerTunnelConfig;

class ClientTunnelPane;

class ServerTunnelPane : public TunnelPane {
    Q_OBJECT

public:
    ServerTunnelPane(TunnelsPageUpdateListener* tunnelsPageUpdateListener, ServerTunnelConfig* tunconf, QWidget* wrongInputPane_, QLabel* wrongInputLabel_, MainWindow* mainWindow);
    virtual ~ServerTunnelPane(){}

    virtual ServerTunnelPane* asServerTunnelPane();
    virtual ClientTunnelPane* asClientTunnelPane();

    int appendServerTunnelForm(ServerTunnelConfig* tunnelConfig, QWidget *tunnelsFormGridLayoutWidget,
                                int tunnelsRow, int height);
    void deleteServerTunnelForm();

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

    //sigType
    QLabel * sigTypeLabel;
    QComboBox * sigTypeComboBox;

protected slots:
    virtual void setGroupBoxTitle(const QString & title);

private:
    void retranslateServerTunnelForm(ServerTunnelPane& /*ui*/) {
        typeLabel->setText(QApplication::translate("srvTunForm", "Server tunnel type:", 0));
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

        sigTypeLabel->setText(QApplication::translate("cltTunForm", "Signature type:", 0));
    }

protected:
    virtual bool applyDataFromUIToTunnelConfig() {
        QString cannotSaveSettings = QApplication::tr("Cannot save settings.");
        bool ok=TunnelPane::applyDataFromUIToTunnelConfig();
        if(!ok)return false;
        ServerTunnelConfig* stc=tunnelConfig->asServerTunnelConfig();
        assert(stc!=nullptr);
        stc->sethost(hostLineEdit->text().toStdString());

        auto portStr=portLineEdit->text();
        int portInt=portStr.toInt(&ok);
        if(!ok){
            highlightWrongInput(QApplication::tr("Bad port, must be int.")+" "+cannotSaveSettings,portLineEdit);
            return false;
        }
        stc->setport(portInt);

        stc->setkeys(keysLineEdit->text().toStdString());

        auto str=inPortLineEdit->text();
        int inPortInt=str.toInt(&ok);
        if(!ok){
            highlightWrongInput(QApplication::tr("Bad inPort, must be int.")+" "+cannotSaveSettings,inPortLineEdit);
            return false;
        }
        stc->setinPort(inPortInt);

        stc->setaccessList(accessListLineEdit->text().toStdString());

        stc->sethostOverride(hostOverrideLineEdit->text().toStdString());

        stc->setwebircpass(webIRCPassLineEdit->text().toStdString());

        stc->setaddress(addressLineEdit->text().toStdString());

        auto mcStr=maxConnsLineEdit->text();
        uint32_t mcInt=(uint32_t)mcStr.toInt(&ok);
        if(!ok){
            highlightWrongInput(QApplication::tr("Bad maxConns, must be int.")+" "+cannotSaveSettings,maxConnsLineEdit);
            return false;
        }
        stc->setmaxConns(mcInt);

        stc->setgzip(gzipCheckBox->isChecked());

        stc->setisUniqueLocal(isUniqueLocalCheckBox->isChecked());

        stc->setsigType(readSigTypeComboboxUI(sigTypeComboBox));
        return true;
    }
};

#endif // SERVERTUNNELPANE_H
