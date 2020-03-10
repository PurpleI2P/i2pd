#ifndef DELAYEDSAVEMANAGER_H
#define DELAYEDSAVEMANAGER_H

#include "Saver.h"

class DelayedSaveManager
{
public:
    DelayedSaveManager();

    virtual void setSaver(Saver* saver)=0;

    typedef unsigned int DATA_SERIAL_TYPE;

    virtual void delayedSave(DATA_SERIAL_TYPE dataSerial, bool needsTunnelFocus, std::string tunnelNameToFocus)=0;

    //returns false iff save failed
    virtual bool appExiting()=0;

    virtual bool needsFocusOnTunnel()=0;
    virtual std::string& getTunnelNameToFocus()=0;
};

#endif // DELAYEDSAVEMANAGER_H
