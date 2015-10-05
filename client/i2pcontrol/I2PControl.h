#ifndef I2PCONTROL_H__
#define I2PCONTROL_H__

#include <boost/property_tree/ptree.hpp>
#include <string>
#include <map>
#include <functional>
#include <mutex>
#include <boost/asio.hpp>

namespace i2p {

// Forward declaration
namespace tunnel { class Tunnel; }

namespace client {
namespace i2pcontrol {

namespace constants {

const char DEFAULT_PASSWORD[] = "itoopie";  
const uint64_t TOKEN_LIFETIME = 600; // Token lifetime in seconds
const std::size_t TOKEN_SIZE = 8; // Token size in bytes

const char PROPERTY_ID[] = "id";
const char PROPERTY_METHOD[] = "method";
const char PROPERTY_PARAMS[] = "params";
const char PROPERTY_RESULT[] = "result";

// methods  
const char METHOD_AUTHENTICATE[] = "Authenticate";
const char METHOD_ECHO[] = "Echo";
const char METHOD_I2PCONTROL[] = "I2PControl";      
const char METHOD_ROUTER_INFO[] = "RouterInfo"; 
const char METHOD_ROUTER_MANAGER[] = "RouterManager";   
const char METHOD_NETWORK_SETTING[] = "NetworkSetting"; 

// params
const char PARAM_API[] = "API";         
const char PARAM_PASSWORD[] = "Password";   
const char PARAM_TOKEN[] = "Token"; 
const char PARAM_ECHO[] = "Echo";   
const char PARAM_RESULT[] = "Result";   

// I2PControl
const char I2PCONTROL_ADDRESS[] = "i2pcontrol.address";     
const char I2PCONTROL_PASSWORD[] = "i2pcontrol.password";
const char I2PCONTROL_PORT[] = "i2pcontrol.port";       

// RouterInfo requests
const char ROUTER_INFO_UPTIME[] = "i2p.router.uptime";
const char ROUTER_INFO_VERSION[] = "i2p.router.version";
const char ROUTER_INFO_STATUS[] = "i2p.router.status";  
const char ROUTER_INFO_DATAPATH[] = "i2p.router.datapath";
const char ROUTER_INFO_NETDB_KNOWNPEERS[] = "i2p.router.netdb.knownpeers";
const char ROUTER_INFO_NETDB_ACTIVEPEERS[] = "i2p.router.netdb.activepeers";
const char ROUTER_INFO_NETDB_FLOODFILLS[] = "i2p.router.netdb.floodfills";        
const char ROUTER_INFO_NETDB_LEASESETS[] = "i2p.router.netdb.leasesets";        
const char ROUTER_INFO_NET_STATUS[] = "i2p.router.net.status";  
const char ROUTER_INFO_TUNNELS_PARTICIPATING[] = "i2p.router.net.tunnels.participating";
// TODO: Probably better to use the standard GetRate instead
const char ROUTER_INFO_TUNNELS_CREATION_SUCCESS[] = "i2p.router.net.tunnels.creationsuccessrate";
const char ROUTER_INFO_TUNNELS_IN_LIST[] = "i2p.router.net.tunnels.inbound.list";
const char ROUTER_INFO_TUNNELS_OUT_LIST[] = "i2p.router.net.tunnels.outbound.list";
const char ROUTER_INFO_BW_IB_1S[] = "i2p.router.net.bw.inbound.1s";
const char ROUTER_INFO_BW_OB_1S[] = "i2p.router.net.bw.outbound.1s";

// RouterManager requests
const char ROUTER_MANAGER_SHUTDOWN[] = "Shutdown";
const char ROUTER_MANAGER_SHUTDOWN_GRACEFUL[] = "ShutdownGraceful";
const char ROUTER_MANAGER_RESEED[] = "Reseed";      

} // constants

/**
 * Represents a Json object, provides functionality to convert to string.
 */
class JsonObject {

public:
    JsonObject() = default;

    JsonObject(const std::string& value);

    JsonObject(int value);

    JsonObject(double value);

    JsonObject& operator[](const std::string& key); 

    std::string toString() const;

private:
    std::map<std::string, JsonObject> children;
    std::string value;
};


JsonObject tunnelToJsonObject(i2p::tunnel::Tunnel* tunnel);

/**
 * "Null" I2P control implementation, does not do actual networking.
 * @note authentication tokens are per-session
 * @note I2PControlSession must always be used as a std::shared_ptr
 * @warning an I2PControlSession must be destroyed before its io_service
 */
class I2PControlSession : public std::enable_shared_from_this<I2PControlSession> {
    
public:
    enum class ErrorCode {
        None = 0,
        // JSON-RPC2
        MethodNotFound = 32601,
        InvalidParameters = 32602,
        InvalidRequest = 32600,
        InternalError = 32603,
        ParseError = 32700,
        // I2PControl specific
        InvalidPassword = 32001,
        NoToken = 32002,
        NonexistentToken = 32003,
        ExpiredToken = 32004,
        UnspecifiedVersion = 32005,
        UnsupportedVersion = 32006
    };

    class Response {
        std::string id;
        std::string version;
        ErrorCode error;
        std::map<std::string, std::string> parameters;

    public:
        Response(const std::string& version = "2.0");
        std::string toJsonString() const;

        /**
         * Set an output parameter to a specified string.
         * @todo escape quotes 
         */
        void setParam(const std::string& param, const std::string& value);

        /**
         * Set an output parameter to a specified integer.
         */
        void setParam(const std::string& param, int value);

        /**
         * Set an output parameter to a specified double.
         */
        void setParam(const std::string& param, double value);

        /**
         * Set an output parameter to a specified Json object.
         */
        void setParam(const std::string& param, const JsonObject& value);

        void setError(ErrorCode code);
        void setId(const std::string& identifier);

        std::string getErrorMsg() const;
    };

    /**
     * Sets up the appropriate handlers.
     * @param pass the password required to authenticate (i.e. obtains a token)
     * @param ios the parent io_service object, must remain valid throughout
     *  the lifetime of this I2PControlSession.
     */
    I2PControlSession(boost::asio::io_service& ios,
        const std::string& pass = constants::DEFAULT_PASSWORD);

    /**
     * Starts the I2PControlSession.
     * In essence, this starts the expireTokensTimer.
     * @note should always be called after construction
     */
    void start();

    /**
     * Cancels all operations that are waiting.
     * @note it's a good idea to call this before destruction (shared_ptr reset)
     */
    void stop();

    /**
     * Handle a json string with I2PControl instructions.
     */
    Response handleRequest(std::stringstream& request);
private:
    // For convenience
    typedef boost::property_tree::ptree PropertyTree;
    // Handler types
    typedef void (I2PControlSession::*MethodHandler)(
        const PropertyTree& pt, Response& results
    );
    typedef void (I2PControlSession::*RequestHandler)(Response& results);
    
    /**
     * Tries to authenticate by checking whether the given token is valid. 
     * Sets the appropriate error code in the given response.
     */
    bool authenticate(const PropertyTree& pt, Response& response);

    /**
     * Generate a random authentication token.
     * @return 8 random bytes as a hexadecimal string
     */
    std::string generateToken() const;

    void startExpireTokensJob();

    /**
     * Expire tokens that are too old.
     */
    void expireTokens(const boost::system::error_code& error);

    // Method handlers
    void handleAuthenticate(const PropertyTree& pt, Response& response);
    void handleEcho(const PropertyTree& pt, Response& response);
    void handleI2PControl(const PropertyTree& pt, Response& response);
    void handleRouterInfo(const PropertyTree& pt, Response& response);
    void handleRouterManager(const PropertyTree& pt, Response& response);
    void handleNetworkSetting(const PropertyTree& pt, Response& response);

    // RouterInfo handlers
    void handleUptime(Response& response);
    void handleVersion(Response& response);
    void handleStatus(Response& response);
    void handleDatapath(Response& response);
    void handleNetDbKnownPeers(Response& response);
    void handleNetDbActivePeers(Response& response);
    void handleNetDbFloodfills(Response& response);
    void handleNetDbLeaseSets(Response& response);
    void handleNetStatus(Response& response);

    void handleTunnelsParticipating(Response& response);
    void handleTunnelsCreationSuccess(Response& response);
    void handleTunnelsInList(Response& response);
    void handleTunnelsOutList(Response& response);

    void handleInBandwidth1S(Response& response);
    void handleOutBandwidth1S(Response& response);

    // RouterManager handlers
    void handleShutdown(Response& response);
    void handleShutdownGraceful(Response& response);
    void handleReseed(Response& response);

    std::string password;
    std::map<std::string, uint64_t> tokens;
    std::mutex tokensMutex;

    std::map<std::string, MethodHandler> methodHandlers;
    std::map<std::string, RequestHandler> routerInfoHandlers;
    std::map<std::string, RequestHandler> routerManagerHandlers;
    std::map<std::string, RequestHandler> networkSettingHandlers;

    boost::asio::io_service& service;
    boost::asio::deadline_timer shutdownTimer;
    boost::asio::deadline_timer expireTokensTimer;
};

}
}
}

#endif // I2PCONTROL_H__
