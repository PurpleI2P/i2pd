#include "TunnelConfig.h"

void TunnelConfig::saveHeaderToStringStream(std::stringstream& out) {
    out << "[" << name << "]\n"
        << "type=" << type.toStdString() << "\n";
}

void TunnelConfig::saveI2CPParametersToStringStream(std::stringstream& out) {
    if (i2cpParameters.getInbound_length().toUShort() != i2p::client::DEFAULT_INBOUND_TUNNEL_LENGTH)
            out << i2p::client::I2CP_PARAM_INBOUND_TUNNEL_LENGTH << "="
                    << i2cpParameters.getInbound_length().toStdString() << "\n";
    if (i2cpParameters.getOutbound_length().toUShort() != i2p::client::DEFAULT_OUTBOUND_TUNNEL_LENGTH)
            out << i2p::client::I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH << "="
                    << i2cpParameters.getOutbound_length().toStdString() << "\n";
    if (i2cpParameters.getInbound_quantity().toUShort() != i2p::client::DEFAULT_INBOUND_TUNNELS_QUANTITY)
            out << i2p::client::I2CP_PARAM_INBOUND_TUNNELS_QUANTITY << "="
                    << i2cpParameters.getInbound_quantity().toStdString() << "\n";
    if (i2cpParameters.getOutbound_quantity().toUShort() != i2p::client::DEFAULT_OUTBOUND_TUNNELS_QUANTITY)
            out << i2p::client::I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY << "="
                    << i2cpParameters.getOutbound_quantity().toStdString() << "\n";
    if (i2cpParameters.getCrypto_tagsToSend().toUShort() != i2p::client::DEFAULT_TAGS_TO_SEND)
            out << i2p::client::I2CP_PARAM_TAGS_TO_SEND << "="
                    << i2cpParameters.getCrypto_tagsToSend().toStdString() << "\n";
    if (!i2cpParameters.getExplicitPeers().isEmpty()) //todo #947
            out << i2p::client::I2CP_PARAM_EXPLICIT_PEERS << "="
                    << i2cpParameters.getExplicitPeers().toStdString() << "\n";
    out << "\n";
}

void ClientTunnelConfig::saveToStringStream(std::stringstream& out) {
    out << "address=" << address << "\n"
        << "port=" << port << "\n"
        << "destination=" << dest << "\n"
        << "keys=" << keys << "\n"
        << "destinationport=" << destinationPort << "\n"
        << "signaturetype=" << sigType << "\n";
}


void ServerTunnelConfig::saveToStringStream(std::stringstream& out) {
    out << "host=" << host << "\n"
        << "port=" << port << "\n"
        << "keys=" << keys << "\n"
        << "signaturetype=" << sigType << "\n"
        << "inport=" << inPort << "\n"
        << "accesslist=" << accessList << "\n"
        << "gzip=" << (gzip?"true":"false") << "\n"
        << "enableuniquelocal=" << (isUniqueLocal?"true":"false") << "\n"
        << "address=" << address << "\n"
        << "hostoverride=" << hostOverride << "\n"
        << "webircpassword=" << webircpass << "\n"
        << "maxconns=" << maxConns << "\n";
}

