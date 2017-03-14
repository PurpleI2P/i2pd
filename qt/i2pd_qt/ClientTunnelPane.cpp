#include "ClientTunnelPane.h"

ClientTunnelPane::ClientTunnelPane()
{

}

void ClientTunnelPane::deleteClientTunnelForm(QGridLayout *tunnelsFormGridLayout) {
    throw "TODO";
    /*TODO
    tunnelsFormGridLayout->removeWidget(clientTunnelNameGroupBox);

    clientTunnelNameGroupBox->deleteLater();
    clientTunnelNameGroupBox=nullptr;

    gridLayoutWidget_2->deleteLater();
    gridLayoutWidget_2=nullptr;
    */
}

ServerTunnelPane* ClientTunnelPane::asServerTunnelPane(){return nullptr;}
ClientTunnelPane* ClientTunnelPane::asClientTunnelPane(){return this;}
