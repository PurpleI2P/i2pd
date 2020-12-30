#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QObject>
#include <QMainWindow>
#include <QPushButton>
#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QAction>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include "QVBoxLayout"
#include "QUrl"

#ifndef ANDROID
# include <QSystemTrayIcon>
# include <QCloseEvent>
# include <QMenu>
#endif

#include <QString>

#include <functional>

#include "MainWindowItems.h"
#include "TunnelPane.h"
#include "ServerTunnelPane.h"
#include "ClientTunnelPane.h"
#include "TunnelConfig.h"
#include "textbrowsertweaked1.h"

#include "Config.h"
#include "FS.h"

#include <QDebug>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include "TunnelsPageUpdateListener.h"

#include "DaemonQT.h"
#include "SignatureTypeComboboxFactory.h"
#include "pagewithbackbutton.h"

#include <iostream>

#include "widgetlockregistry.h"
#include "widgetlock.h"

#include "DelayedSaveManager.h"
#include "DelayedSaveManagerImpl.h"
#include "SaverImpl.h"

#include "I2pdQtUtil.h"

class SaverImpl;

class LogViewerManager;

template<typename ValueType>
bool isType(boost::any& a) {
    return
#ifdef BOOST_AUX_ANY_TYPE_ID_NAME
            std::strcmp(a.type().name(), typeid(ValueType).name()) == 0
#else
            a.type() == typeid(ValueType)
#endif
            ;
}

class ConfigOption {
public:
    QString section;
    QString option;
    //MainWindow::DefaultValueGetter defaultValueGetter;
    ConfigOption(QString section_, QString option_/*, DefaultValueGetter defaultValueGetter_*/):
        section(section_)
      , option(option_)
      //, defaultValueGetter(defaultValueGetter_)
    {}

};

extern std::string programOptionsWriterCurrentSection;

class MainWindow;

class MainWindowItem : public QObject {
    Q_OBJECT
private:
    ConfigOption option;
    QWidget* widgetToFocus;
    QString requirementToBeValid;
    const bool readOnly;
public:
    MainWindowItem(ConfigOption option_, QWidget* widgetToFocus_, QString requirementToBeValid_, bool readOnly_=false) :
        option(option_), widgetToFocus(widgetToFocus_), requirementToBeValid(requirementToBeValid_), readOnly(readOnly_) {}
    QWidget* getWidgetToFocus(){return widgetToFocus;}
    QString& getRequirementToBeValid() { return requirementToBeValid; }
    ConfigOption& getConfigOption() { return option; }
    boost::any optionValue;
    virtual ~MainWindowItem(){}
    virtual void installListeners(MainWindow *mainWindow);
    virtual void loadFromConfigOption(){
        std::string optName="";
        if(!option.section.isEmpty())optName=option.section.toStdString()+std::string(".");
        optName+=option.option.toStdString();
        //qDebug() << "loadFromConfigOption[" << optName.c_str() << "]";
        boost::any programOption;
        i2p::config::GetOptionAsAny(optName, programOption);
        optionValue=programOption.empty()?boost::any(std::string(""))
                   :boost::any_cast<boost::program_options::variable_value>(programOption).value();
    }
    virtual void saveToStringStream(std::stringstream& out){
        if(readOnly)return; //should readOnly items (conf=) error somewhere, instead of silently skipping save?
        if(isType<std::string>(optionValue)) {
            std::string v = boost::any_cast<std::string>(optionValue);
            if(v.empty())return;
        }
        if(optionValue.empty())return;
        std::string rtti = optionValue.type().name();
        std::string optName="";
        if(!option.section.isEmpty())optName=option.section.toStdString()+std::string(".");
        optName+=option.option.toStdString();
        //qDebug() << "Writing option" << optName.c_str() << "of type" << rtti.c_str();
        std::string sectionAsStdStr = option.section.toStdString();
        if(!option.section.isEmpty() &&
                sectionAsStdStr!=programOptionsWriterCurrentSection) {
            out << "[" << sectionAsStdStr << "]\n";
            programOptionsWriterCurrentSection=sectionAsStdStr;
        }
        out << option.option.toStdString() << "=";
        if(isType<std::string>(optionValue)) {
            out << boost::any_cast<std::string>(optionValue);
        }else if(isType<bool>(optionValue)) {
            out << (boost::any_cast<bool>(optionValue) ? "true" : "false");
        }else if(isType<uint16_t>(optionValue)) {
            out << boost::any_cast<uint16_t>(optionValue);
        }else if(isType<uint32_t>(optionValue)) {
            out << boost::any_cast<uint32_t>(optionValue);
        }else if(isType<int>(optionValue)) {
            out << boost::any_cast<int>(optionValue);
        }else if(isType<unsigned short>(optionValue)) {
            out << boost::any_cast<unsigned short>(optionValue);
        }else out << boost::any_cast<std::string>(optionValue); //let it throw
        out << "\n\n";
    }
    virtual bool isValid(bool & alreadyDisplayedIfWrong){alreadyDisplayedIfWrong=false;return true;}
};
class NonGUIOptionItem : public MainWindowItem {
public:
    NonGUIOptionItem(ConfigOption option_) : MainWindowItem(option_, nullptr, QString()) {}
    virtual ~NonGUIOptionItem(){}
    //virtual bool isValid(bool & alreadyDisplayedIfWrong) { return true; }
};
class BaseStringItem : public MainWindowItem {
    Q_OBJECT
public:
    QLineEdit* lineEdit;
    MainWindow *mainWindow;
    BaseStringItem(ConfigOption option_, QLineEdit* lineEdit_, QString requirementToBeValid_, MainWindow* mainWindow_, bool readOnly=false):
        MainWindowItem(option_, lineEdit_, requirementToBeValid_, readOnly),
        lineEdit(lineEdit_),
        mainWindow(mainWindow_)
    {};
    virtual ~BaseStringItem(){}
    virtual void installListeners(MainWindow *mainWindow);
    virtual QString toString(){
        return boost::any_cast<std::string>(optionValue).c_str();
    }
    virtual boost::any fromString(QString s){return boost::any(s.toStdString());}
    virtual void loadFromConfigOption(){
        MainWindowItem::loadFromConfigOption();
        lineEdit->setText(toString());
    }

    virtual void saveToStringStream(std::stringstream& out){
        optionValue=fromString(lineEdit->text());
        MainWindowItem::saveToStringStream(out);
    }
    virtual bool isValid(bool & alreadyDisplayedIfWrong);
};
class FileOrFolderChooserItem : public BaseStringItem {
protected:
    const bool requireExistingFile;
public:
    QPushButton* browsePushButton;
    FileOrFolderChooserItem(ConfigOption option_, QLineEdit* lineEdit_, QPushButton* browsePushButton_, MainWindow* mw, bool requireExistingFile_, bool readOnly) :
        BaseStringItem(option_, lineEdit_, QString(), mw, readOnly), requireExistingFile(requireExistingFile_), browsePushButton(browsePushButton_) {}
    virtual ~FileOrFolderChooserItem(){}
};
class FileChooserItem : public FileOrFolderChooserItem {
    Q_OBJECT
private slots:
    void pushButtonReleased();
public:
    FileChooserItem(ConfigOption option_, QLineEdit* lineEdit_, QPushButton* browsePushButton_, MainWindow* mw, bool requireExistingFile, bool readOnly) :
        FileOrFolderChooserItem(option_, lineEdit_, browsePushButton_, mw, requireExistingFile, readOnly) {
        QObject::connect(browsePushButton, SIGNAL(released()), this, SLOT(pushButtonReleased()));
    }
};
class FolderChooserItem : public FileOrFolderChooserItem{
    Q_OBJECT
private slots:
    void pushButtonReleased();
public:
    FolderChooserItem(ConfigOption option_, QLineEdit* lineEdit_, QPushButton* browsePushButton_, MainWindow* mw, bool requireExistingFolder) :
        FileOrFolderChooserItem(option_, lineEdit_, browsePushButton_, mw, requireExistingFolder, false) {
        QObject::connect(browsePushButton, SIGNAL(released()), this, SLOT(pushButtonReleased()));
    }
};
class ComboBoxItem : public MainWindowItem {
public:
    QComboBox* comboBox;
    ComboBoxItem(ConfigOption option_, QComboBox* comboBox_) : MainWindowItem(option_,comboBox_,QString()), comboBox(comboBox_){}
    virtual ~ComboBoxItem(){}
    virtual void installListeners(MainWindow *mainWindow);
    virtual void loadFromConfigOption()=0;
    virtual void saveToStringStream(std::stringstream& out)=0;
    //virtual bool isValid(bool & alreadyDisplayedIfWrong) { return ; }
};
class LogDestinationComboBoxItem : public ComboBoxItem {
public:
    LogDestinationComboBoxItem(ConfigOption option_, QComboBox* comboBox_) :
        ComboBoxItem(option_, comboBox_) {}
    virtual ~LogDestinationComboBoxItem(){}
    virtual void loadFromConfigOption(){
        MainWindowItem::loadFromConfigOption();
        const char * ld = boost::any_cast<std::string>(optionValue).c_str();
        comboBox->setCurrentText(QString(ld));
    }
    virtual void saveToStringStream(std::stringstream& out){
        std::string logDest = comboBox->currentText().toStdString();
        optionValue=logDest;
        MainWindowItem::saveToStringStream(out);
    }
    //virtual bool isValid(bool & alreadyDisplayedIfWrong) { return true; }

    Q_OBJECT
};
class LogLevelComboBoxItem : public ComboBoxItem {
public:
    LogLevelComboBoxItem(ConfigOption option_, QComboBox* comboBox_) : ComboBoxItem(option_, comboBox_) {}
    virtual ~LogLevelComboBoxItem(){}
    virtual void loadFromConfigOption(){
        MainWindowItem::loadFromConfigOption();
        const char * ll = boost::any_cast<std::string>(optionValue).c_str();
        comboBox->setCurrentText(QString(ll));
    }
    virtual void saveToStringStream(std::stringstream& out){
        optionValue=comboBox->currentText().toStdString();
        MainWindowItem::saveToStringStream(out);
    }
    //virtual bool isValid(bool & alreadyDisplayedIfWrong) { return true; }
};
class SignatureTypeComboBoxItem : public ComboBoxItem {
public:
    SignatureTypeComboBoxItem(ConfigOption option_, QComboBox* comboBox_) : ComboBoxItem(option_, comboBox_) {}
    virtual ~SignatureTypeComboBoxItem(){}
    virtual void loadFromConfigOption(){
        MainWindowItem::loadFromConfigOption();
        while(comboBox->count()>0)comboBox->removeItem(0);
        uint16_t selected = (uint16_t) boost::any_cast<unsigned short>(optionValue);
        SignatureTypeComboBoxFactory::fillComboBox(comboBox, selected);
    }
    virtual void saveToStringStream(std::stringstream& out){
        uint16_t selected = SignatureTypeComboBoxFactory::getSigType(comboBox->currentData());
        optionValue=(unsigned short)selected;
        MainWindowItem::saveToStringStream(out);
    }
    //virtual bool isValid(bool & alreadyDisplayedIfWrong) { return true; }
};
class CheckBoxItem : public MainWindowItem {
public:
    QCheckBox* checkBox;
    CheckBoxItem(ConfigOption option_, QCheckBox* checkBox_) : MainWindowItem(option_,checkBox_,QString()), checkBox(checkBox_){}
    virtual ~CheckBoxItem(){}
    virtual void installListeners(MainWindow *mainWindow);
    virtual void loadFromConfigOption(){
        MainWindowItem::loadFromConfigOption();
        //qDebug() << "setting value for checkbox " << checkBox->text();
        checkBox->setChecked(boost::any_cast<bool>(optionValue));
    }
    virtual void saveToStringStream(std::stringstream& out){
        optionValue=checkBox->isChecked();
        MainWindowItem::saveToStringStream(out);
    }
    //virtual bool isValid(bool & alreadyDisplayedIfWrong) { return true; }
};
class BaseFormattedStringItem : public BaseStringItem {
public:
    QString fieldNameTranslated;
    BaseFormattedStringItem(ConfigOption option_, QLineEdit* lineEdit_, QString fieldNameTranslated_, QString requirementToBeValid_, MainWindow* mw) :
        BaseStringItem(option_, lineEdit_, requirementToBeValid_, mw), fieldNameTranslated(fieldNameTranslated_) {}
    virtual ~BaseFormattedStringItem(){}
    //virtual bool isValid(bool & alreadyDisplayedIfWrong)=0;
};
class IntegerStringItem : public BaseFormattedStringItem {
public:
    IntegerStringItem(ConfigOption option_, QLineEdit* lineEdit_, QString fieldNameTranslated_, MainWindow* mw) :
        BaseFormattedStringItem(option_, lineEdit_, fieldNameTranslated_, QApplication::tr("Must be a valid integer."), mw) {}
    virtual ~IntegerStringItem(){}
    virtual bool isValid(bool & alreadyDisplayedIfWrong){
        bool correct = BaseFormattedStringItem::isValid(alreadyDisplayedIfWrong);
        if(!correct)return false;
        alreadyDisplayedIfWrong = false;
        auto str=lineEdit->text();
        bool ok;
        str.toInt(&ok);
        return ok;
    }
    virtual QString toString(){return QString::number(boost::any_cast<int>(optionValue));}
    virtual boost::any fromString(QString s){return boost::any(std::stoi(s.toStdString()));}
};
class UShortStringItem : public BaseFormattedStringItem {
public:
    UShortStringItem(ConfigOption option_, QLineEdit* lineEdit_, QString fieldNameTranslated_, MainWindow* mw) :
        BaseFormattedStringItem(option_, lineEdit_, fieldNameTranslated_, QApplication::tr("Must be unsigned short integer."), mw) {}
    virtual ~UShortStringItem(){}
    virtual bool isValid(bool & alreadyDisplayedIfWrong){
        bool correct = BaseFormattedStringItem::isValid(alreadyDisplayedIfWrong);
        if(!correct)return false;
        alreadyDisplayedIfWrong = false;
        auto str=lineEdit->text();
        bool ok;
        str.toUShort(&ok);
        return ok;
    }
    virtual QString toString(){return QString::number(boost::any_cast<unsigned short>(optionValue));}
    virtual boost::any fromString(QString s){return boost::any((unsigned short)std::stoi(s.toStdString()));}
};
class UInt32StringItem : public BaseFormattedStringItem {
public:
    UInt32StringItem(ConfigOption option_, QLineEdit* lineEdit_, QString fieldNameTranslated_, MainWindow* mw) :
        BaseFormattedStringItem(option_, lineEdit_, fieldNameTranslated_, QApplication::tr("Must be unsigned 32-bit integer."), mw) {}
    virtual ~UInt32StringItem(){}
    virtual bool isValid(bool & alreadyDisplayedIfWrong){
        bool correct = BaseFormattedStringItem::isValid(alreadyDisplayedIfWrong);
        if(!correct)return false;
        alreadyDisplayedIfWrong = false;
        auto str=lineEdit->text();
        bool ok;
        str.toUInt(&ok);
        return ok;
    }
    virtual QString toString(){return QString::number(boost::any_cast<uint32_t>(optionValue));}
    virtual boost::any fromString(QString s){return boost::any((uint32_t)std::stoi(s.toStdString()));}
};
class UInt16StringItem : public BaseFormattedStringItem {
public:
    UInt16StringItem(ConfigOption option_, QLineEdit* lineEdit_, QString fieldNameTranslated_, MainWindow* mw) :
        BaseFormattedStringItem(option_, lineEdit_, fieldNameTranslated_, QApplication::tr("Must be unsigned 16-bit integer."), mw) {}
    virtual ~UInt16StringItem(){}
    virtual bool isValid(bool & alreadyDisplayedIfWrong){
        bool correct = BaseFormattedStringItem::isValid(alreadyDisplayedIfWrong);
        if(!correct)return false;
        alreadyDisplayedIfWrong = false;
        auto str=lineEdit->text();
        bool ok;
        str.toUShort(&ok);
        return ok;
    }
    virtual QString toString(){return QString::number(boost::any_cast<uint16_t>(optionValue));}
    virtual boost::any fromString(QString s){return boost::any((uint16_t)std::stoi(s.toStdString()));}
};
class IPAddressStringItem : public BaseFormattedStringItem {
public:
    IPAddressStringItem(ConfigOption option_, QLineEdit* lineEdit_, QString fieldNameTranslated_, MainWindow* mw) :
        BaseFormattedStringItem(option_, lineEdit_, fieldNameTranslated_, QApplication::tr("Must be an IPv4 address"), mw) {}
    //virtual bool isValid(bool & alreadyDisplayedIfWrong){return true;}//todo
};
class TCPPortStringItem : public UShortStringItem {
public:
    TCPPortStringItem(ConfigOption option_, QLineEdit* lineEdit_, QString fieldNameTranslated_, MainWindow* mw) :
        UShortStringItem(option_, lineEdit_, fieldNameTranslated_,mw) {}
};

namespace Ui {
  class MainWindow;
  class StatusButtonsForm;
  class routerCommandsWidget;
  class GeneralSettingsContentsForm;
}

using namespace i2p::client;

class TunnelPane;

using namespace i2p::qt;

class Controller;

class DelayedSaveManagerImpl;

class MainWindow : public QMainWindow {
    Q_OBJECT
private:
    std::string currentLocalDestinationB32;
    std::shared_ptr<std::iostream> logStream;
    DelayedSaveManagerImpl* delayedSaveManagerPtr;
    DelayedSaveManager::DATA_SERIAL_TYPE dataSerial;
public:
    explicit MainWindow(std::shared_ptr<std::iostream> logStream_, QWidget *parent=nullptr);
    ~MainWindow();

    void setI2PController(i2p::qt::Controller* controller_);

    void highlightWrongInput(QString warningText, WrongInputPageEnum inputPage, QWidget* widgetToFocus);

    //typedef std::function<QString ()> DefaultValueGetter;

//#ifndef ANDROID
//    void setVisible(bool visible);
//#endif

private:
    enum StatusPage {main_page, commands, local_destinations, leasesets, tunnels, transit_tunnels,
                     transports, i2p_tunnels, sam_sessions};
private slots:
    void updated();

    void handleQuitButton();
    void handleGracefulQuitButton();
    void handleDoRestartButton();
    void handleGracefulQuitTimerEvent();
#ifndef ANDROID
    void setIcon();
    void iconActivated(QSystemTrayIcon::ActivationReason reason);
    void toggleVisibilitySlot();
#endif
    void scheduleStatusPageUpdates();
    void statusHtmlPageMouseReleased();
    void statusHtmlPageSelectionChanged();
    void updateStatusPage();

    void showStatusMainPage();
    void showStatus_commands_Page();
    void runPeerTest();
    void enableTransit();
    void disableTransit();

public slots:
    void syncLogLevel (int comboBoxIndex);

    void showStatus_local_destinations_Page();
    void showStatus_leasesets_Page();
    void showStatus_tunnels_Page();
    void showStatus_transit_tunnels_Page();
    void showStatus_transports_Page();
    void showStatus_i2p_tunnels_Page();
    void showStatus_sam_sessions_Page();

    void showLogViewerPage();
    void showSettingsPage();
    void showTunnelsPage();
    void showRestartPage();
    void showQuitPage();
    void showAboutBox(const QString & href);

private:
    StatusPage statusPage;
    QTimer * statusPageUpdateTimer;
    bool wasSelectingAtStatusMainPage;
    bool showHiddenInfoStatusMainPage;

    LogViewerManager *logViewerManagerPtr;

    void showStatusPage(StatusPage newStatusPage);
#ifndef ANDROID
    void createActions();
    void createTrayIcon();
    bool quitting;
    QAction *toggleWindowVisibleAction;
    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;
#endif

public:
    Ui::MainWindow* ui;
    Ui::StatusButtonsForm* statusButtonsUI;
    Ui::routerCommandsWidget* routerCommandsUI;
    Ui::GeneralSettingsContentsForm* uiSettings;
    void adjustSizesAccordingToWrongLabel();
    bool applyTunnelsUiToConfigs();
private:
    int settingsTitleLabelNominalHeight;
    TextBrowserTweaked1 * textBrowser;
    QWidget * routerCommandsParent;
    PageWithBackButton * pageWithBackButton;
    TextBrowserTweaked1 * childTextBrowser;

    widgetlockregistry widgetlocks;

    i2p::qt::Controller* i2pController;

protected:

    void updateRouterCommandsButtons();

#ifndef ANDROID
    void closeEvent(QCloseEvent *event);
#endif
    void resizeEvent(QResizeEvent* event);
    void onResize();

    void setStatusButtonsVisible(bool visible);

    QString getStatusPageHtml(bool showHiddenInfo);

    QList<MainWindowItem*> configItems;
    NonGUIOptionItem* daemonOption;
    NonGUIOptionItem* serviceOption;
    //LogDestinationComboBoxItem* logOption;
    FileChooserItem* logFileNameOption;

    FileChooserItem* initFileChooser(ConfigOption option, QLineEdit* fileNameLineEdit, QPushButton* fileBrowsePushButton, bool requireExistingFile, bool readOnly=false);
    void initFolderChooser(ConfigOption option, QLineEdit* folderLineEdit, QPushButton* folderBrowsePushButton);
    //void initCombobox(ConfigOption option, QComboBox* comboBox);
    void initLogDestinationCombobox(ConfigOption option, QComboBox* comboBox);
    void initLogLevelCombobox(ConfigOption option, QComboBox* comboBox);
    void initSignatureTypeCombobox(ConfigOption option, QComboBox* comboBox);
    void initIPAddressBox(ConfigOption option, QLineEdit* addressLineEdit, QString fieldNameTranslated);
    void initTCPPortBox(ConfigOption option, QLineEdit* portLineEdit, QString fieldNameTranslated);
    void initCheckBox(ConfigOption option, QCheckBox* checkBox);
    void initIntegerBox(ConfigOption option, QLineEdit* numberLineEdit, QString fieldNameTranslated);
    void initUInt32Box(ConfigOption option, QLineEdit* numberLineEdit, QString fieldNameTranslated);
    void initUInt16Box(ConfigOption option, QLineEdit* numberLineEdit, QString fieldNameTranslated);
    void initStringBox(ConfigOption option, QLineEdit* lineEdit);
    NonGUIOptionItem* initNonGUIOption(ConfigOption option);

    void loadAllConfigs(SaverImpl* saverPtr);
    void layoutTunnels();

public slots:
    /** returns false iff not valid items present and save was aborted */
    bool saveAllConfigs(bool reloadAfterSave, FocusEnum focusOn, std::string tunnelNameToFocus="", QWidget* widgetToFocus=nullptr);
    void reloadTunnelsConfigAndUI(std::string tunnelNameToFocus, QWidget* widgetToFocus);
    void reloadTunnelsConfigAndUI() { reloadTunnelsConfigAndUI("", nullptr); }

    //focus none
    void reloadTunnelsConfigAndUI_QString(QString tunnelNameToFocus);
    void addServerTunnelPushButtonReleased();
    void addClientTunnelPushButtonReleased();

    void anchorClickedHandler(const QUrl & link);
    void backClickedFromChild();

    void logDestinationComboBoxValueChanged(const QString & text);

private:
    QString datadir;
    QString confpath;
    QString tunconfpath;

    std::map<std::string, TunnelConfig*> tunnelConfigs;
    std::list<TunnelPane*> tunnelPanes;

    void appendTunnelForms(std::string tunnelNameToFocus);
    void deleteTunnelForms();
    void deleteTunnelFromUI(std::string tunnelName, TunnelConfig* cnf);

    template<typename Section>
    std::string GetI2CPOption (const Section& section, const std::string& name, const std::string& value) const
    {
        return section.second.get (boost::property_tree::ptree::path_type (name, '/'), value);
    }

    template<typename Section>
    std::string GetI2CPOption (const Section& section, const std::string& name, const char* value) const
    {
        return section.second.get (boost::property_tree::ptree::path_type (name, '/'), std::string (value));
    }

    template<typename Section, typename Type>
    std::string GetI2CPOption (const Section& section, const std::string& name, const Type& value) const
    {
        return section.second.get (boost::property_tree::ptree::path_type (name, '/'), std::to_string (value));
    }

    template<typename Section>
    void ReadI2CPOptions (const Section& section, std::map<std::string, std::string>& options, I2CPParameters& param
                          /*TODO fill param*/) const
    {
        std::string _INBOUND_TUNNEL_LENGTH = options[I2CP_PARAM_INBOUND_TUNNEL_LENGTH] = GetI2CPOption (section, I2CP_PARAM_INBOUND_TUNNEL_LENGTH,  DEFAULT_INBOUND_TUNNEL_LENGTH);
        param.setInbound_length(QString(_INBOUND_TUNNEL_LENGTH.c_str()));
        std::string _OUTBOUND_TUNNEL_LENGTH = options[I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH] = GetI2CPOption (section, I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH, DEFAULT_OUTBOUND_TUNNEL_LENGTH);
        param.setOutbound_length(QString(_OUTBOUND_TUNNEL_LENGTH.c_str()));
        std::string _INBOUND_TUNNELS_QUANTITY = options[I2CP_PARAM_INBOUND_TUNNELS_QUANTITY] = GetI2CPOption (section, I2CP_PARAM_INBOUND_TUNNELS_QUANTITY, DEFAULT_INBOUND_TUNNELS_QUANTITY);
        param.setInbound_quantity( QString(_INBOUND_TUNNELS_QUANTITY.c_str()));
        std::string _OUTBOUND_TUNNELS_QUANTITY = options[I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY] = GetI2CPOption (section, I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY, DEFAULT_OUTBOUND_TUNNELS_QUANTITY);
        param.setOutbound_quantity(QString(_OUTBOUND_TUNNELS_QUANTITY.c_str()));
        std::string _TAGS_TO_SEND = options[I2CP_PARAM_TAGS_TO_SEND] = GetI2CPOption (section, I2CP_PARAM_TAGS_TO_SEND, DEFAULT_TAGS_TO_SEND);
        param.setCrypto_tagsToSend(QString(_TAGS_TO_SEND.c_str()));
        std::string _i2cp_leaseSetAuthType = options[I2CP_PARAM_LEASESET_AUTH_TYPE] = GetI2CPOption (section, I2CP_PARAM_LEASESET_AUTH_TYPE, 0);
        param.set_i2cp_leaseSetAuthType(QString(_i2cp_leaseSetAuthType.c_str()));
        const char DEFAULT_LEASESET_ENCRYPTION_TYPE[] = "";
        std::string _i2cp_leaseSetEncType = options[I2CP_PARAM_LEASESET_ENCRYPTION_TYPE] = GetI2CPOption (section, I2CP_PARAM_LEASESET_ENCRYPTION_TYPE, DEFAULT_LEASESET_ENCRYPTION_TYPE);//todo Identity's type by default
        param.set_i2cp_leaseSetEncType(QString(_i2cp_leaseSetEncType.c_str()));
        std::string _i2cp_leaseSetPrivKey = options[I2CP_PARAM_LEASESET_PRIV_KEY] = GetI2CPOption (section, I2CP_PARAM_LEASESET_PRIV_KEY, "");
        param.set_i2cp_leaseSetPrivKey(QString(_i2cp_leaseSetPrivKey.c_str()));
        std::string _i2cp_leaseSetType = options[I2CP_PARAM_LEASESET_TYPE] = GetI2CPOption (section, I2CP_PARAM_LEASESET_TYPE, DEFAULT_LEASESET_TYPE);
        param.set_i2cp_leaseSetType(QString(_i2cp_leaseSetType.c_str()));
        std::string _i2p_streaming_answerPings= options[I2CP_PARAM_STREAMING_ANSWER_PINGS] = GetI2CPOption (section, I2CP_PARAM_STREAMING_ANSWER_PINGS, DEFAULT_ANSWER_PINGS);
        param.set_i2p_streaming_answerPings((_i2p_streaming_answerPings.compare("true")==0)||(_i2p_streaming_answerPings.compare("yes")==0));
        std::string _i2p_streaming_initialAckDelay = options[I2CP_PARAM_STREAMING_INITIAL_ACK_DELAY] = GetI2CPOption (section, I2CP_PARAM_STREAMING_INITIAL_ACK_DELAY, DEFAULT_INITIAL_ACK_DELAY);
        param.set_i2p_streaming_initialAckDelay(QString(_i2p_streaming_initialAckDelay.c_str()));
        options[I2CP_PARAM_MIN_TUNNEL_LATENCY] = GetI2CPOption(section, I2CP_PARAM_MIN_TUNNEL_LATENCY, DEFAULT_MIN_TUNNEL_LATENCY);//TODO include into param
        options[I2CP_PARAM_MAX_TUNNEL_LATENCY] = GetI2CPOption(section, I2CP_PARAM_MAX_TUNNEL_LATENCY, DEFAULT_MAX_TUNNEL_LATENCY);//TODO include into param
    }

    void CreateDefaultI2CPOptions (I2CPParameters& param
                          /*TODO fill param*/) const
    {
        const int _INBOUND_TUNNEL_LENGTH = DEFAULT_INBOUND_TUNNEL_LENGTH;
        param.setInbound_length(QString::number(_INBOUND_TUNNEL_LENGTH));
        const int _OUTBOUND_TUNNEL_LENGTH = DEFAULT_OUTBOUND_TUNNEL_LENGTH;
        param.setOutbound_length(QString::number(_OUTBOUND_TUNNEL_LENGTH));
        const int _INBOUND_TUNNELS_QUANTITY = DEFAULT_INBOUND_TUNNELS_QUANTITY;
        param.setInbound_quantity( QString::number(_INBOUND_TUNNELS_QUANTITY));
        const int _OUTBOUND_TUNNELS_QUANTITY = DEFAULT_OUTBOUND_TUNNELS_QUANTITY;
        param.setOutbound_quantity(QString::number(_OUTBOUND_TUNNELS_QUANTITY));
        const int _TAGS_TO_SEND = DEFAULT_TAGS_TO_SEND;
        param.setCrypto_tagsToSend(QString::number(_TAGS_TO_SEND));
        const int _i2cp_leaseSetAuthType = 0;
        param.set_i2cp_leaseSetAuthType(QString::number(_i2cp_leaseSetAuthType));
        const QString _i2cp_leaseSetEncType = "0,4"; //todo Identity's type by default
        param.set_i2cp_leaseSetEncType(_i2cp_leaseSetEncType);
        param.set_i2cp_leaseSetPrivKey("");
        const int _i2cp_leaseSetType = DEFAULT_LEASESET_TYPE;
        param.set_i2cp_leaseSetType(QString::number(_i2cp_leaseSetType));
        bool _i2p_streaming_answerPings= DEFAULT_ANSWER_PINGS;
        param.set_i2p_streaming_answerPings(_i2p_streaming_answerPings);
        const int _i2p_streaming_initialAckDelay = DEFAULT_INITIAL_ACK_DELAY;
        param.set_i2p_streaming_initialAckDelay(QString::number(_i2p_streaming_initialAckDelay));
    }


    void DeleteTunnelNamed(std::string name) {
        std::map<std::string,TunnelConfig*>::const_iterator it=tunnelConfigs.find(name);
        if(it!=tunnelConfigs.end()){
            TunnelConfig* tc=it->second;
            deleteTunnelFromUI(name, tc);
            tunnelConfigs.erase(it);
            delete tc;
        }
        saveAllConfigs(true, FocusEnum::noFocus);
    }

    std::string GenerateNewTunnelName() {
        int i=1;
        while(true){
            std::stringstream name;
            name << "name" << i;
            const std::string& str=name.str();
            if(tunnelConfigs.find(str)==tunnelConfigs.end())return str;
            ++i;
        }
    }

    void CreateDefaultClientTunnel() {//TODO dedup default values with ReadTunnelsConfig() and with ClientContext.cpp::ReadTunnels ()
        std::string name=GenerateNewTunnelName();
        std::string type = I2P_TUNNELS_SECTION_TYPE_CLIENT;
        std::string dest = "127.0.0.1";
        int port = 0;
        std::string keys = "";
        std::string address = "127.0.0.1";
        int destinationPort = 0;
        int cryptoType = 0;
        i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256;
        // I2CP
        I2CPParameters i2cpParameters;
        CreateDefaultI2CPOptions (i2cpParameters);

        tunnelConfigs[name]=new ClientTunnelConfig(name, QString(type.c_str()), i2cpParameters,
                                                      dest,
                                                      port,
                                                      keys,
                                                      address,
                                                      destinationPort,
                                                      sigType,
                                                      cryptoType);

        saveAllConfigs(true, FocusEnum::focusOnTunnelName, name);
    }

    void CreateDefaultServerTunnel() {//TODO dedup default values with ReadTunnelsConfig() and with ClientContext.cpp::ReadTunnels ()
        std::string name=GenerateNewTunnelName();
        std::string type=I2P_TUNNELS_SECTION_TYPE_SERVER;
        std::string host = "127.0.0.1";
        int port = 0;
        std::string keys = "";
        int inPort = 0;
        std::string accessList = "";
        std::string hostOverride = "";
        std::string webircpass = "";
        bool gzip = true;
        i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256;
        std::string address = "127.0.0.1";
        bool isUniqueLocal = true;
        int cryptoType = 0;

        // I2CP
        I2CPParameters i2cpParameters;
        CreateDefaultI2CPOptions (i2cpParameters);

        tunnelConfigs[name]=new ServerTunnelConfig(name, QString(type.c_str()), i2cpParameters,
                                                  host,
                                                  port,
                                                  keys,
                                                  inPort,
                                                  accessList,
                                                  hostOverride,
                                                  webircpass,
                                                  gzip,
                                                  sigType,
                                                  address,
                                                  isUniqueLocal,
                                                  cryptoType);


        saveAllConfigs(true, FocusEnum::focusOnTunnelName, name);
    }

    void ReadTunnelsConfig() //TODO deduplicate the code with ClientContext.cpp::ReadTunnels ()
    {
        boost::property_tree::ptree pt;
        std::string tunConf=tunconfpath.toStdString();
        if (tunConf == "") {
            // TODO: cleanup this in 2.8.0
            tunConf = i2p::fs::DataDirPath ("tunnels.cfg");
            if (i2p::fs::Exists(tunConf)) {
                LogPrint(eLogWarning, "FS: please rename tunnels.cfg -> tunnels.conf here: ", tunConf);
            } else {
                tunConf = i2p::fs::DataDirPath ("tunnels.conf");
            }
        }
        LogPrint(eLogDebug, "tunnels config file: ", tunConf);
        try
        {
            boost::property_tree::read_ini (tunConf, pt);
        }
        catch (std::exception& ex)
        {
            LogPrint (eLogWarning, "Clients: Can't read ", tunConf, ": ", ex.what ());//TODO show err box and disable tunn.page
            return;
        }

        for (auto& section: pt)
        {
            std::string name = section.first;
            try
            {
                std::string type = section.second.get<std::string> (I2P_TUNNELS_SECTION_TYPE);
                if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT
                        || type == I2P_TUNNELS_SECTION_TYPE_SOCKS
                        || type == I2P_TUNNELS_SECTION_TYPE_WEBSOCKS
                        || type == I2P_TUNNELS_SECTION_TYPE_HTTPPROXY
                        || type == I2P_TUNNELS_SECTION_TYPE_UDPCLIENT)
                {
                    // mandatory params
                    std::string dest;
                    if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT || type == I2P_TUNNELS_SECTION_TYPE_UDPCLIENT) {
                        dest = section.second.get<std::string> (I2P_CLIENT_TUNNEL_DESTINATION);
                    }
                    int port = section.second.get<int> (I2P_CLIENT_TUNNEL_PORT);
                    // optional params
                    std::string keys = section.second.get (I2P_CLIENT_TUNNEL_KEYS, "");
                    std::string address = section.second.get (I2P_CLIENT_TUNNEL_ADDRESS, "127.0.0.1");
                    int cryptoType = section.second.get<int>(I2P_CLIENT_TUNNEL_CRYPTO_TYPE, 0);
                    int destinationPort = section.second.get<int>(I2P_CLIENT_TUNNEL_DESTINATION_PORT, 0);
                    i2p::data::SigningKeyType sigType = section.second.get (I2P_CLIENT_TUNNEL_SIGNATURE_TYPE, i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
                    // I2CP
                    std::map<std::string, std::string> options;
                    I2CPParameters i2cpParameters;
                    ReadI2CPOptions (section, options, i2cpParameters);

                    tunnelConfigs[name]=new ClientTunnelConfig(name, QString(type.c_str()), i2cpParameters,
                                                              dest,
                                                              port,
                                                              keys,
                                                              address,
                                                              destinationPort,
                                                              sigType,
                                                              cryptoType);
                }
                else if (type == I2P_TUNNELS_SECTION_TYPE_SERVER
                                 || type == I2P_TUNNELS_SECTION_TYPE_HTTP
                                 || type == I2P_TUNNELS_SECTION_TYPE_IRC
                                 || type == I2P_TUNNELS_SECTION_TYPE_UDPSERVER)
                {
                    // mandatory params
                    std::string host = section.second.get<std::string> (I2P_SERVER_TUNNEL_HOST);
                    int port = section.second.get<int> (I2P_SERVER_TUNNEL_PORT);
                    // optional params
                    std::string keys = section.second.get<std::string> (I2P_SERVER_TUNNEL_KEYS, "");
                    int inPort = section.second.get (I2P_SERVER_TUNNEL_INPORT, 0);
                    std::string accessList = section.second.get (I2P_SERVER_TUNNEL_ACCESS_LIST, "");
                    std::string hostOverride = section.second.get (I2P_SERVER_TUNNEL_HOST_OVERRIDE, "");
                    std::string webircpass = section.second.get<std::string> (I2P_SERVER_TUNNEL_WEBIRC_PASSWORD, "");
                    bool gzip = section.second.get (I2P_SERVER_TUNNEL_GZIP, true);
                    i2p::data::SigningKeyType sigType = section.second.get (I2P_SERVER_TUNNEL_SIGNATURE_TYPE, i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
                    std::string address = section.second.get<std::string> (I2P_SERVER_TUNNEL_ADDRESS, "127.0.0.1");
                    bool isUniqueLocal = section.second.get(I2P_SERVER_TUNNEL_ENABLE_UNIQUE_LOCAL, true);
                    int cryptoType = section.second.get<int>(I2P_CLIENT_TUNNEL_CRYPTO_TYPE, 0);

                    // I2CP
                    std::map<std::string, std::string> options;
                    I2CPParameters i2cpParameters;
                    ReadI2CPOptions (section, options, i2cpParameters);

                    /*
                    std::set<i2p::data::IdentHash> idents;
                    if (accessList.length () > 0)
                    {
                        size_t pos = 0, comma;
                        do
                        {
                            comma = accessList.find (',', pos);
                            i2p::data::IdentHash ident;
                            ident.FromBase32 (accessList.substr (pos, comma != std::string::npos ? comma - pos : std::string::npos));
                            idents.insert (ident);
                            pos = comma + 1;
                        }
                        while (comma != std::string::npos);
                    }
                    */
                    tunnelConfigs[name]=new ServerTunnelConfig(name, QString(type.c_str()), i2cpParameters,
                                                              host,
                                                              port,
                                                              keys,
                                                              inPort,
                                                              accessList,
                                                              hostOverride,
                                                              webircpass,
                                                              gzip,
                                                              sigType,
                                                              address,
                                                              isUniqueLocal,
                                                              cryptoType);
                }
                else
                    LogPrint (eLogWarning, "Clients: Unknown section type=", type, " of ", name, " in ", tunConf);//TODO show err box and disable the tunn gui

            }
            catch (std::exception& ex)
            {
                LogPrint (eLogError, "Clients: Can't read tunnel ", name, " params: ", ex.what ());//TODO show err box and disable the tunn gui
            }
        }
    }

private:
    class TunnelsPageUpdateListenerMainWindowImpl : public TunnelsPageUpdateListener {
        MainWindow* mainWindow;
    public:
        TunnelsPageUpdateListenerMainWindowImpl(MainWindow* mainWindow_):mainWindow(mainWindow_){}
        virtual void updated(std::string oldName, TunnelConfig* tunConf);
        virtual void needsDeleting(std::string oldName);
    };

    TunnelsPageUpdateListenerMainWindowImpl tunnelsPageUpdateListener;

    //void onLoggingOptionsChange() {}

    SaverImpl* saverPtr;
};

#endif // MAINWINDOW_H
