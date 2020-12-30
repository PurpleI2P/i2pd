#ifndef SAVERIMPL_H
#define SAVERIMPL_H

#include <map>
#include <string>

#include <QObject>
#include "QList"

#include "mainwindow.h"
#include "TunnelConfig.h"
#include "Saver.h"

class MainWindowItem;
class TunnelConfig;

class SaverImpl : public Saver
{
public:
    SaverImpl(MainWindow *mainWindowPtr_, QList<MainWindowItem*> * configItems_, std::map<std::string,TunnelConfig*>* tunnelConfigs_);
    virtual ~SaverImpl();
    virtual bool save(bool reloadAfterSave, const FocusEnum focusOn, const std::string& tunnelNameToFocus, QWidget* widgetToFocus);
    void setConfPath(QString& confpath_);
    void setTunnelsConfPath(QString& tunconfpath_);
private:
    QList<MainWindowItem*> * configItems;
    std::map<std::string,TunnelConfig*>* tunnelConfigs;
    QString confpath;
    QString tunconfpath;
    MainWindow* mainWindowPtr;
};

#endif // SAVERIMPL_H
