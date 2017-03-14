#ifndef CLIENTTUNNELPANE_H
#define CLIENTTUNNELPANE_H

#include "QGridLayout"

#include "TunnelPane.h"

class ServerTunnelPane;
class TunnelPane;

class ClientTunnelPane : public TunnelPane {
public:
    ClientTunnelPane();
    virtual ServerTunnelPane* asServerTunnelPane();
    virtual ClientTunnelPane* asClientTunnelPane();
    void deleteClientTunnelForm(QGridLayout *tunnelsFormGridLayout);
protected slots:
    virtual void setGroupBoxTitle(const QString & title){}//TODO
};

#endif // CLIENTTUNNELPANE_H
