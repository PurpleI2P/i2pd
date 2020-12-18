#ifndef SAVER_H
#define SAVER_H

#include <string>
#include <QObject>
#include <QString>
class QWidget;

#include "I2pdQtTypes.h"

class Saver : public QObject
{
    Q_OBJECT

public:
    Saver();
    //FocusEnum::focusNone iff failures //??? wtf
    virtual bool save(bool reloadAfterSave, const FocusEnum focusOn, const std::string& tunnelNameToFocus="", QWidget* widgetToFocus=nullptr)=0;

signals:
    void reloadTunnelsConfigAndUISignal(const QString);

};

#endif // SAVER_H
