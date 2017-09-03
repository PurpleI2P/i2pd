#include "TunnelConfig.h"

void TunnelConfig::saveHeaderToStringStream(std::stringstream& out) {
    out << "[" << name << "]\n"
        << "type=" << type.toStdString() << "\n";
}

void TunnelConfig::saveI2CPParametersToStringStream(std::stringstream& out) {
    if (i2cpParameters.getInbound_length().toUShort() != 3)
        out << "inbound.length=" << i2cpParameters.getInbound_length().toStdString() << "\n";
    if (i2cpParameters.getOutbound_length().toUShort() != 3)
        out << "outbound.length=" << i2cpParameters.getOutbound_length().toStdString() << "\n";
    if (i2cpParameters.getInbound_quantity().toUShort() != 5)
        out << "inbound.quantity=" << i2cpParameters.getInbound_quantity().toStdString() << "\n";
    if (i2cpParameters.getOutbound_quantity().toUShort() != 5)
        out << "outbound.quantity=" << i2cpParameters.getOutbound_quantity().toStdString() << "\n";
    if (i2cpParameters.getCrypto_tagsToSend().toUShort() != 40)
        out << "crypto.tagsToSend=" << i2cpParameters.getCrypto_tagsToSend().toStdString() << "\n";
    if (!i2cpParameters.getExplicitPeers().isEmpty())
        out << "explicitPeers=" << i2cpParameters.getExplicitPeers().toStdString() << "\n";
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

