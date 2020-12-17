#ifndef DELAYEDSAVEMANAGER_H
#define DELAYEDSAVEMANAGER_H

#include "Saver.h"
#include "I2pdQtTypes.h"

class DelayedSaveManager
{
public:
    DelayedSaveManager();

    virtual void setSaver(Saver* saver)=0;

    typedef unsigned int DATA_SERIAL_TYPE;

    virtual void delayedSave(bool reloadAfterSave, DATA_SERIAL_TYPE dataSerial, FocusEnum focusOn, std::string tunnelNameToFocus, QWidget* widgetToFocus)=0;

    //returns false iff save failed
    virtual bool appExiting()=0;

    virtual FocusEnum getFocusOn()=0;
    virtual std::string& getTunnelNameToFocus()=0;
    virtual QWidget* getWidgetToFocus()=0;
};

#endif // DELAYEDSAVEMANAGER_H
