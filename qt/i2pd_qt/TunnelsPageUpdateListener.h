#ifndef TUNNELSPAGEUPDATELISTENER_H
#define TUNNELSPAGEUPDATELISTENER_H

class TunnelConfig;

class TunnelsPageUpdateListener {
public:
    virtual void updated(std::string oldName, TunnelConfig* tunConf)=0;
    virtual void needsDeleting(std::string oldName)=0;
};

#endif // TUNNELSPAGEUPDATELISTENER_H
