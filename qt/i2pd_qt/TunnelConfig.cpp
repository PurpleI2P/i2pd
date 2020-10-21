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
    out << i2p::client::I2CP_PARAM_LEASESET_AUTH_TYPE << "="
            << i2cpParameters.get_i2cp_leaseSetAuthType().toStdString() << "\n";
    out << i2p::client::I2CP_PARAM_LEASESET_ENCRYPTION_TYPE << "="
            << i2cpParameters.get_i2cp_leaseSetEncType().toStdString() << "\n";
    out << i2p::client::I2CP_PARAM_LEASESET_PRIV_KEY << "="
            << i2cpParameters.get_i2cp_leaseSetPrivKey().toStdString() << "\n";
    out << i2p::client::I2CP_PARAM_LEASESET_TYPE << "="
            << i2cpParameters.get_i2cp_leaseSetType().toStdString() << "\n";
    out << i2p::client::I2CP_PARAM_STREAMING_ANSWER_PINGS << "="
            << (i2cpParameters.get_i2p_streaming_answerPings() ? "true" : "false") << "\n";
    out << i2p::client::I2CP_PARAM_STREAMING_INITIAL_ACK_DELAY << "="
            << i2cpParameters.get_i2p_streaming_initialAckDelay().toStdString() << "\n";
    out << "\n";
}

void ClientTunnelConfig::saveToStringStream(std::stringstream& out) {
    out << "address=" << address << "\n"
        << "port=" << port << "\n"
        << "destination=" << dest << "\n"
        << "destinationport=" << destinationPort << "\n"
        << "cryptoType=" << getcryptoType() << "\n"
        << "signaturetype=" << sigType << "\n";
    if(!keys.empty()) out << "keys=" << keys << "\n";
}


void ServerTunnelConfig::saveToStringStream(std::stringstream& out) {
    out << "host=" << host << "\n"
        << "port=" << port << "\n"
        << "signaturetype=" << sigType << "\n"
        << "inport=" << inPort << "\n";
    if(accessList.size()>0) { out << "accesslist=" << accessList << "\n"; }
    out << "gzip=" << (gzip?"true":"false") << "\n"
        << "cryptoType=" << getcryptoType() << "\n"
        << "enableuniquelocal=" << (isUniqueLocal?"true":"false") << "\n"
        << "address=" << address << "\n"
        << "hostoverride=" << hostOverride << "\n"
        << "webircpassword=" << webircpass << "\n";
    if(!keys.empty()) out << "keys=" << keys << "\n";
}

