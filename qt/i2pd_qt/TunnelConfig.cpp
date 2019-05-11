#include "TunnelConfig.h"

void TunnelConfig::saveHeaderToStringStream(std::stringstream& out) {
    out << "[" << name << "]\n"
        << "type=" << type.toStdString() << "\n";
}

void TunnelConfig::saveDNCPParametersToStringStream(std::stringstream& out) {
    if (dncpParameters.getInbound_length().toUShort() != dotnet::client::DEFAULT_INBOUND_TUNNEL_LENGTH)
            out << dotnet::client::DNCP_PARAM_INBOUND_TUNNEL_LENGTH << "="
                    << dncpParameters.getInbound_length().toStdString() << "\n";
    if (dncpParameters.getOutbound_length().toUShort() != dotnet::client::DEFAULT_OUTBOUND_TUNNEL_LENGTH)
            out << dotnet::client::DNCP_PARAM_OUTBOUND_TUNNEL_LENGTH << "="
                    << dncpParameters.getOutbound_length().toStdString() << "\n";
    if (dncpParameters.getInbound_quantity().toUShort() != dotnet::client::DEFAULT_INBOUND_TUNNELS_QUANTITY)
            out << dotnet::client::DNCP_PARAM_INBOUND_TUNNELS_QUANTITY << "="
                    << dncpParameters.getInbound_quantity().toStdString() << "\n";
    if (dncpParameters.getOutbound_quantity().toUShort() != dotnet::client::DEFAULT_OUTBOUND_TUNNELS_QUANTITY)
            out << dotnet::client::DNCP_PARAM_OUTBOUND_TUNNELS_QUANTITY << "="
                    << dncpParameters.getOutbound_quantity().toStdString() << "\n";
    if (dncpParameters.getCrypto_tagsToSend().toUShort() != dotnet::client::DEFAULT_TAGS_TO_SEND)
            out << dotnet::client::DNCP_PARAM_TAGS_TO_SEND << "="
                    << dncpParameters.getCrypto_tagsToSend().toStdString() << "\n";
    if (!dncpParameters.getExplicitPeers().isEmpty()) //todo #947
            out << dotnet::client::DNCP_PARAM_EXPLICIT_PEERS << "="
                    << dncpParameters.getExplicitPeers().toStdString() << "\n";
    out << "\n";
}

void ClientTunnelConfig::saveToStringStream(std::stringstream& out) {
    out << "address=" << address << "\n"
        << "port=" << port << "\n"
        << "destination=" << dest << "\n"
        << "destinationport=" << destinationPort << "\n"
        << "signaturetype=" << sigType << "\n";
    if(!keys.empty()) out << "keys=" << keys << "\n";
}


void ServerTunnelConfig::saveToStringStream(std::stringstream& out) {
    out << "host=" << host << "\n"
        << "port=" << port << "\n"
        << "signaturetype=" << sigType << "\n"
        << "inport=" << inPort << "\n"
        << "accesslist=" << accessList << "\n"
        << "gzip=" << (gzip?"true":"false") << "\n"
        << "enableuniquelocal=" << (isUniqueLocal?"true":"false") << "\n"
        << "address=" << address << "\n"
        << "hostoverride=" << hostOverride << "\n"
        << "webircpassword=" << webircpass << "\n";
    if(!keys.empty()) out << "keys=" << keys << "\n";
}

