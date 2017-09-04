#ifndef TUNNELCONFIG_H
#define TUNNELCONFIG_H

#include "QString"
#include <string>

#include "../../libi2pd_client/ClientContext.h"
#include "../../libi2pd/Destination.h"
#include "TunnelsPageUpdateListener.h"


class I2CPParameters{
    QString inbound_length;//number of hops of an inbound tunnel. 3 by default; lower value is faster but dangerous
    QString outbound_length;//number of hops of an outbound tunnel. 3 by default; lower value is faster but dangerous
    QString inbound_quantity; //number of inbound tunnels. 5 by default
    QString outbound_quantity; //number of outbound tunnels. 5 by default
    QString crypto_tagsToSend; //number of ElGamal/AES tags to send. 40 by default; too low value may cause problems with tunnel building
    QString explicitPeers; //list of comma-separated b64 addresses of peers to use, default: unset
public:
    I2CPParameters(): inbound_length(),
                                 outbound_length(),
                                 inbound_quantity(),
                                 outbound_quantity(),
                                 crypto_tagsToSend(),
                                 explicitPeers() {}
    const QString& getInbound_length(){return inbound_length;}
    const QString& getOutbound_length(){return outbound_length;}
    const QString& getInbound_quantity(){return inbound_quantity;}
    const QString& getOutbound_quantity(){return outbound_quantity;}
    const QString& getCrypto_tagsToSend(){return crypto_tagsToSend;}
    const QString& getExplicitPeers(){return explicitPeers;}
    void setInbound_length(QString inbound_length_){inbound_length=inbound_length_;}
    void setOutbound_length(QString outbound_length_){outbound_length=outbound_length_;}
    void setInbound_quantity(QString inbound_quantity_){inbound_quantity=inbound_quantity_;}
    void setOutbound_quantity(QString outbound_quantity_){outbound_quantity=outbound_quantity_;}
    void setCrypto_tagsToSend(QString crypto_tagsToSend_){crypto_tagsToSend=crypto_tagsToSend_;}
    void setExplicitPeers(QString explicitPeers_){explicitPeers=explicitPeers_;}
};


class ClientTunnelConfig;
class ServerTunnelConfig;
class TunnelConfig {
    /*
    const char I2P_TUNNELS_SECTION_TYPE_CLIENT[] = "client";
    const char I2P_TUNNELS_SECTION_TYPE_SERVER[] = "server";
    const char I2P_TUNNELS_SECTION_TYPE_HTTP[] = "http";
    const char I2P_TUNNELS_SECTION_TYPE_IRC[] = "irc";
    const char I2P_TUNNELS_SECTION_TYPE_UDPCLIENT[] = "udpclient";
    const char I2P_TUNNELS_SECTION_TYPE_UDPSERVER[] = "udpserver";
    const char I2P_TUNNELS_SECTION_TYPE_SOCKS[] = "socks";
    const char I2P_TUNNELS_SECTION_TYPE_WEBSOCKS[] = "websocks";
    const char I2P_TUNNELS_SECTION_TYPE_HTTPPROXY[] = "httpproxy";
    */
    QString type;
    std::string name;
public:
    TunnelConfig(std::string name_, QString& type_, I2CPParameters& i2cpParameters_):
        type(type_), name(name_), i2cpParameters(i2cpParameters_) {}
    virtual ~TunnelConfig(){}
    const QString& getType(){return type;}
    const std::string& getName(){return name;}
    void setType(const QString& type_){type=type_;}
    void setName(const std::string& name_){name=name_;}
    I2CPParameters& getI2cpParameters(){return i2cpParameters;}
    void saveHeaderToStringStream(std::stringstream& out);
    void saveI2CPParametersToStringStream(std::stringstream& out);
    virtual void saveToStringStream(std::stringstream& out)=0;
    virtual ClientTunnelConfig* asClientTunnelConfig()=0;
    virtual ServerTunnelConfig* asServerTunnelConfig()=0;

private:
    I2CPParameters i2cpParameters;
};

/*
# mandatory parameters:
    std::string dest;
    if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT || type == I2P_TUNNELS_SECTION_TYPE_UDPCLIENT)
        dest = section.second.get<std::string> (I2P_CLIENT_TUNNEL_DESTINATION);
    int port = section.second.get<int> (I2P_CLIENT_TUNNEL_PORT);
# optional parameters (may be omitted)
    std::string keys = section.second.get (I2P_CLIENT_TUNNEL_KEYS, "");
    std::string address = section.second.get (I2P_CLIENT_TUNNEL_ADDRESS, "127.0.0.1");
    int destinationPort = section.second.get (I2P_CLIENT_TUNNEL_DESTINATION_PORT, 0);
    i2p::data::SigningKeyType sigType = section.second.get (I2P_CLIENT_TUNNEL_SIGNATURE_TYPE, i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
# * keys -- our identity, if unset, will be generated on every startup,
#     if set and file missing, keys will be generated and placed to this file
# * address -- local interface to bind
# * signaturetype -- signature type for new destination. 0 (DSA/SHA1), 1 (EcDSA/SHA256) or 7 (EdDSA/SHA512)
[somelabel]
type = client
address = 127.0.0.1
port = 6668
destination = irc.postman.i2p
keys = irc-keys.dat
*/
class ClientTunnelConfig : public TunnelConfig {
    std::string dest;
    int port;
    std::string keys;
    std::string address;
    int destinationPort;
    i2p::data::SigningKeyType sigType;
public:
    ClientTunnelConfig(std::string name_, QString type_, I2CPParameters& i2cpParameters_,
                       std::string dest_,
                       int port_,
                       std::string keys_,
                       std::string address_,
                       int destinationPort_,
                       i2p::data::SigningKeyType sigType_): TunnelConfig(name_, type_, i2cpParameters_),
        dest(dest_),
        port(port_),
        keys(keys_),
        address(address_),
        destinationPort(destinationPort_),
        sigType(sigType_){}
    std::string& getdest(){return dest;}
    int getport(){return port;}
    std::string & getkeys(){return keys;}
    std::string & getaddress(){return address;}
    int getdestinationPort(){return destinationPort;}
    i2p::data::SigningKeyType getsigType(){return sigType;}
    void setdest(const std::string& dest_){dest=dest_;}
    void setport(int port_){port=port_;}
    void setkeys(const std::string & keys_){keys=keys_;}
    void setaddress(const std::string & address_){address=address_;}
    void setdestinationPort(int destinationPort_){destinationPort=destinationPort_;}
    void setsigType(i2p::data::SigningKeyType sigType_){sigType=sigType_;}
    virtual void saveToStringStream(std::stringstream& out);
    virtual ClientTunnelConfig* asClientTunnelConfig(){return this;}
    virtual ServerTunnelConfig* asServerTunnelConfig(){return nullptr;}
};

/*
# mandatory parameters:
# * host -- ip address of our service
# * port -- port of our service
# * keys -- file with LeaseSet of address in i2p
    std::string host = section.second.get<std::string> (I2P_SERVER_TUNNEL_HOST);
    int port = section.second.get<int> (I2P_SERVER_TUNNEL_PORT);
    std::string keys = section.second.get<std::string> (I2P_SERVER_TUNNEL_KEYS);
# optional parameters (may be omitted)
    int inPort = section.second.get (I2P_SERVER_TUNNEL_INPORT, 0);
    std::string accessList = section.second.get (I2P_SERVER_TUNNEL_ACCESS_LIST, "");
    std::string hostOverride = section.second.get (I2P_SERVER_TUNNEL_HOST_OVERRIDE, "");
    std::string webircpass = section.second.get<std::string> (I2P_SERVER_TUNNEL_WEBIRC_PASSWORD, "");
    bool gzip = section.second.get (I2P_SERVER_TUNNEL_GZIP, true);
    i2p::data::SigningKeyType sigType = section.second.get (I2P_SERVER_TUNNEL_SIGNATURE_TYPE, i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
    uint32_t maxConns = section.second.get(i2p::stream::I2CP_PARAM_STREAMING_MAX_CONNS_PER_MIN, i2p::stream::DEFAULT_MAX_CONNS_PER_MIN);
    std::string address = section.second.get<std::string> (I2P_SERVER_TUNNEL_ADDRESS, "127.0.0.1");
    bool isUniqueLocal = section.second.get(I2P_SERVER_TUNNEL_ENABLE_UNIQUE_LOCAL, true);
# * inport -- optional, i2p service port, if unset - the same as 'port'
# * accesslist -- comma-separated list of i2p addresses, allowed to connect
#    every address is b32 without '.b32.i2p' part
[somelabel]
type = server
host = 127.0.0.1
port = 6667
keys = irc.dat
*/
class ServerTunnelConfig : public TunnelConfig {
    std::string host;
    int port;
    std::string keys;
    int inPort;
    std::string accessList;
    std::string hostOverride;
    std::string webircpass;
    bool gzip;
    i2p::data::SigningKeyType sigType;
    uint32_t maxConns;
    std::string address;
    bool isUniqueLocal;
public:
    ServerTunnelConfig(std::string name_, QString type_, I2CPParameters& i2cpParameters_,
                       std::string host_,
                       int port_,
                       std::string keys_,
                       int inPort_,
                       std::string accessList_,
                       std::string hostOverride_,
                       std::string webircpass_,
                       bool gzip_,
                       i2p::data::SigningKeyType sigType_,
                       uint32_t maxConns_,
                       std::string address_,
                       bool isUniqueLocal_): TunnelConfig(name_, type_, i2cpParameters_),
        host(host_),
        port(port_),
        keys(keys_),
        inPort(inPort_),
        accessList(accessList_),
        hostOverride(hostOverride_),
        webircpass(webircpass_),
        gzip(gzip_),
        sigType(sigType_),
        maxConns(maxConns_),
        address(address_),
        isUniqueLocal(isUniqueLocal_) {}
    std::string& gethost(){return host;}
    int getport(){return port;}
    std::string& getkeys(){return keys;}
    int getinPort(){return inPort;}
    std::string& getaccessList(){return accessList;}
    std::string& gethostOverride(){return hostOverride;}
    std::string& getwebircpass(){return webircpass;}
    bool getgzip(){return gzip;}
    i2p::data::SigningKeyType getsigType(){return sigType;}
    uint32_t getmaxConns(){return maxConns;}
    std::string& getaddress(){return address;}
    bool getisUniqueLocal(){return isUniqueLocal;}
    void sethost(const std::string& host_){host=host_;}
    void setport(int port_){port=port_;}
    void setkeys(const std::string& keys_){keys=keys_;}
    void setinPort(int inPort_){inPort=inPort_;}
    void setaccessList(const std::string& accessList_){accessList=accessList_;}
    void sethostOverride(const std::string& hostOverride_){hostOverride=hostOverride_;}
    void setwebircpass(const std::string& webircpass_){webircpass=webircpass_;}
    void setgzip(bool gzip_){gzip=gzip_;}
    void setsigType(i2p::data::SigningKeyType sigType_){sigType=sigType_;}
    void setmaxConns(uint32_t maxConns_){maxConns=maxConns_;}
    void setaddress(const std::string& address_){address=address_;}
    void setisUniqueLocal(bool isUniqueLocal_){isUniqueLocal=isUniqueLocal_;}
    virtual void saveToStringStream(std::stringstream& out);
    virtual ClientTunnelConfig* asClientTunnelConfig(){return nullptr;}
    virtual ServerTunnelConfig* asServerTunnelConfig(){return this;}
};


#endif // TUNNELCONFIG_H
