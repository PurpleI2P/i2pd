// There is bug in boost 1.49 with gcc 4.7 coming with Debian Wheezy
// #define GCC47_BOOST149 ((BOOST_VERSION == 104900) && (__GNUC__ == 4) && (__GNUC_MINOR__ == 7))
// TODO: handle this somewhere, but definitely not here

#include "I2PControl.h"
#include <iomanip>
#include <sstream>

#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

#include <boost/property_tree/json_parser.hpp>
#include "util/Log.h"
#include "util/Timestamp.h"
#include "transport/Transports.h"
#include "tunnel/Tunnel.h"
#include "NetDb.h"
#include "version.h"
#include "Daemon.h"

namespace i2p {
namespace client {

I2PControlSession::Response::Response(const std::string& version)
    : id(), version(version), error(ErrorCode::None), parameters()
{

}

std::string I2PControlSession::Response::toJsonString() const
{
    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"result\":{";                  
    for(auto it = parameters.begin(); it != parameters.end(); ++it) {
        if(it != parameters.begin())
            oss << ',';
        oss << '"' << it->first << "\":" << it->second;
    }
    oss << "},\"jsonrpc\":\"" << version << '"';
    if(error != ErrorCode::None)
        oss << ",\"error\":{\"code\":" << -static_cast<int>(error)
            << ",\"message\":\"" << getErrorMsg() << "\"" << "}";
    oss << "}";
    return oss.str();
}

std::string I2PControlSession::Response::getErrorMsg() const
{
    switch(error) {
        case ErrorCode::MethodNotFound:
            return "Method not found.";
        case ErrorCode::InvalidParameters:
            return "Invalid parameters.";
        case ErrorCode::InvalidRequest:
            return "Invalid request.";
        case ErrorCode::ParseError:
            return "Json parse error.";
        case ErrorCode::InvalidPassword:
            return "Invalid password.";
        case ErrorCode::NoToken:
            return "No authentication token given.";
        case ErrorCode::NonexistentToken:
            return "Nonexistent authentication token given.";
        case ErrorCode::ExpiredToken:
            return "Exipred authentication token given.";
        case ErrorCode::UnspecifiedVersion:
            return "Version not specified.";
        case ErrorCode::UnsupportedVersion:
            return "Version not supported.";
        default:
            return "";
    };
}

void I2PControlSession::Response::setParam(const std::string& param, const std::string& value)
{
    parameters[param] = value.empty() ? "null" : "\"" + value + "\"";
}

void I2PControlSession::Response::setParam(const std::string& param, int value)
{
    parameters[param] = std::to_string(value);  
}

void I2PControlSession::Response::setParam(const std::string& param, double value)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << value;
    parameters[param] = oss.str();
}

void I2PControlSession::Response::setError(ErrorCode code)
{
    error = code;
}

void I2PControlSession::Response::setId(const std::string& identifier)
{
    id = identifier;
}

I2PControlSession::I2PControlSession(boost::asio::io_service& ios)
    : password(I2P_CONTROL_DEFAULT_PASSWORD), tokens(), tokensMutex(),
      service(ios), shutdownTimer(ios), expireTokensTimer(ios)
{
    // Method handlers
    methodHandlers[I2P_CONTROL_METHOD_AUTHENTICATE] = &I2PControlSession::handleAuthenticate; 
    methodHandlers[I2P_CONTROL_METHOD_ECHO] = &I2PControlSession::handleEcho;
    methodHandlers[I2P_CONTROL_METHOD_I2PCONTROL] = &I2PControlSession::handleI2PControl;
    methodHandlers[I2P_CONTROL_METHOD_ROUTER_INFO] = &I2PControlSession::handleRouterInfo;
    methodHandlers[I2P_CONTROL_METHOD_ROUTER_MANAGER] = &I2PControlSession::handleRouterManager;
    methodHandlers[I2P_CONTROL_METHOD_NETWORK_SETTING] = &I2PControlSession::handleNetworkSetting; 
    // RouterInfo handlers
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_UPTIME] = &I2PControlSession::handleUptime;
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_VERSION] = &I2PControlSession::handleVersion;
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_STATUS] = &I2PControlSession::handleStatus;
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS]= &I2PControlSession::handleNetDbKnownPeers;
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_NETDB_ACTIVEPEERS] = &I2PControlSession::handleNetDbActivePeers;
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_NET_STATUS] = &I2PControlSession::handleNetStatus;
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_TUNNELS_PARTICIPATING] = &I2PControlSession::handleTunnelsParticipating;
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_BW_IB_1S] = &I2PControlSession::handleInBandwidth1S;
    routerInfoHandlers[I2P_CONTROL_ROUTER_INFO_BW_OB_1S] = &I2PControlSession::handleOutBandwidth1S;

    // RouterManager handlers
    routerManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN] = &I2PControlSession::handleShutdown; 
    routerManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN_GRACEFUL] = &I2PControlSession::handleShutdownGraceful;
    routerManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_RESEED] = &I2PControlSession::handleReseed;
}

void I2PControlSession::start()
{
    startExpireTokensJob();
}

void I2PControlSession::stop()
{
    boost::system::error_code e; // Make sure this doesn't throw
    shutdownTimer.cancel(e);
    expireTokensTimer.cancel(e);
}

I2PControlSession::Response I2PControlSession::handleRequest(std::stringstream& request)
{
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(request, pt);

    Response response;
    try { 
        response.setId(pt.get<std::string>(I2P_CONTROL_PROPERTY_ID));

        std::string method = pt.get<std::string>(I2P_CONTROL_PROPERTY_METHOD);
        auto it = methodHandlers.find(method);
        if(it == methodHandlers.end()) { // Not found
            LogPrint(eLogWarning, "Unknown I2PControl method ", method);
            response.setError(ErrorCode::MethodNotFound);
            return response;
        }

        PropertyTree params = pt.get_child(I2P_CONTROL_PROPERTY_PARAMS);
        if(method != I2P_CONTROL_METHOD_AUTHENTICATE && !authenticate(params, response)) {
            LogPrint(eLogWarning, "I2PControl invalid token presented");
            return response;
        }
        // Call the appropriate handler
        (this->*(it->second))(params, response);

    } catch(const boost::property_tree::ptree_error& error) {
        response.setError(ErrorCode::ParseError);
    } catch(...) {
        response.setError(ErrorCode::InternalError);
    }

    return response;
}

bool I2PControlSession::authenticate(const PropertyTree& pt, Response& response)
{
    try {
        std::string token = pt.get<std::string>(I2P_CONTROL_PARAM_TOKEN); 

        std::lock_guard<std::mutex> lock(tokensMutex);
        auto it = tokens.find(token);
        if(it == tokens.end()) {
            response.setError(ErrorCode::NonexistentToken);
            return false;
        } else if(util::GetSecondsSinceEpoch() - it->second > I2P_CONTROL_TOKEN_LIFETIME) {
            response.setError(ErrorCode::ExpiredToken);
            return false; 
        }

    } catch(const boost::property_tree::ptree_error& error) {
        response.setError(ErrorCode::NoToken);
        return false;
    }

    return true;
}

std::string I2PControlSession::generateToken() const
{
    byte random_data[I2P_CONTROL_TOKEN_SIZE] = {};
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(random_data, I2P_CONTROL_TOKEN_SIZE);
    std::string token;
    CryptoPP::StringSource ss(
        random_data, I2P_CONTROL_TOKEN_SIZE, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(token))
    );
    return token;
}

void I2PControlSession::handleAuthenticate(const PropertyTree& pt, Response& response)
{
    const int api = pt.get<int>(I2P_CONTROL_PARAM_API);
    const std::string given_pass = pt.get<std::string>(I2P_CONTROL_PARAM_PASSWORD);
    LogPrint(eLogDebug, "I2PControl Authenticate API = ", api, " Password = ", password);
    if(given_pass != password) {
        LogPrint(
            eLogError, "I2PControl Authenticate Invalid password ", password,
            " expected ", password
        );
        response.setError(ErrorCode::InvalidPassword);
        return;
    }
    const std::string token = generateToken();
    response.setParam(I2P_CONTROL_PARAM_API, api);
    response.setParam(I2P_CONTROL_PARAM_TOKEN, token);

    std::lock_guard<std::mutex> lock(tokensMutex);
    tokens.insert(std::make_pair(token, util::GetSecondsSinceEpoch()));
}

void I2PControlSession::handleEcho(const PropertyTree& pt, Response& response)
{
    const std::string echo = pt.get<std::string>(I2P_CONTROL_PARAM_ECHO);
    LogPrint(eLogDebug, "I2PControl Echo Echo = ", echo);
    response.setParam(I2P_CONTROL_PARAM_RESULT, echo);
}

void I2PControlSession::handleI2PControl(const PropertyTree& pt, Response& response)
{
    LogPrint(eLogDebug, "I2PControl I2PControl");
    // TODO: implement
    
}

void I2PControlSession::handleRouterInfo(const PropertyTree& pt, Response& response)
{
    LogPrint(eLogDebug, "I2PControl RouterInfo");
    for(const auto& pair : pt) {
        if(pair.first == I2P_CONTROL_PARAM_TOKEN)
            continue;
        LogPrint(eLogDebug, pair.first);
        auto it = routerInfoHandlers.find(pair.first);
        if(it != routerInfoHandlers.end()) {
            (this->*(it->second))(response);
        } else {
            LogPrint(eLogError, "I2PControl RouterInfo unknown request ", pair.first);
            response.setError(ErrorCode::InvalidRequest);
        }
    }
}

void I2PControlSession::handleRouterManager(const PropertyTree& pt, Response& response)
{
    LogPrint(eLogDebug, "I2PControl RouterManager");
    for(const auto& pair : pt) {
        if(pair.first == I2P_CONTROL_PARAM_TOKEN)
            continue;
        LogPrint(eLogDebug, pair.first);
        auto it = routerManagerHandlers.find(pair.first);
        if(it != routerManagerHandlers.end()) {
            (this->*(it->second))(response);
        } else {
            LogPrint(eLogError, "I2PControl RouterManager unknown request ", pair.first);
            response.setError(ErrorCode::InvalidRequest);
        }
    }
}

void I2PControlSession::handleNetworkSetting(const PropertyTree& pt, Response& response)
{

}

void I2PControlSession::handleUptime(Response& response)
{
    response.setParam(I2P_CONTROL_ROUTER_INFO_UPTIME, (int)i2p::context.GetUptime()*1000);
}

void I2PControlSession::handleVersion(Response& response)
{
    response.setParam(I2P_CONTROL_ROUTER_INFO_VERSION, VERSION);    
}

void I2PControlSession::handleStatus(Response& response)
{
    response.setParam(I2P_CONTROL_ROUTER_INFO_STATUS, "???"); // TODO:
}

void I2PControlSession::handleNetDbKnownPeers(Response& response)
{
    response.setParam(
        I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS, i2p::data::netdb.GetNumRouters()
    );
}

void I2PControlSession::handleNetDbActivePeers(Response& response)
{
    response.setParam(
        I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS,
        i2p::data::netdb.GetNumRouters()
    );
}

void I2PControlSession::handleNetStatus(Response& response)
{
    response.setParam(
        I2P_CONTROL_ROUTER_INFO_NETDB_ACTIVEPEERS,
        (int)i2p::transport::transports.GetPeers().size()
    );  
}

void I2PControlSession::handleTunnelsParticipating(Response& response)
{
    response.setParam(
        I2P_CONTROL_ROUTER_INFO_TUNNELS_PARTICIPATING,
        (int)i2p::tunnel::tunnels.GetTransitTunnels().size()
    );
}

void I2PControlSession::handleInBandwidth1S(Response& response)
{
    response.setParam(
        I2P_CONTROL_ROUTER_INFO_BW_IB_1S,
        (double)i2p::transport::transports.GetInBandwidth()
    );
}

void I2PControlSession::handleOutBandwidth1S(Response& response)
{
    response.setParam(
        I2P_CONTROL_ROUTER_INFO_BW_OB_1S,
        (double)i2p::transport::transports.GetOutBandwidth()
    );
}

void I2PControlSession::handleShutdown(Response& response)
{
    LogPrint(eLogInfo, "Shutdown requested");
    response.setParam(I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN, "");
    // 1 second to make sure response has been sent
    shutdownTimer.expires_from_now(boost::posix_time::seconds(1));
    shutdownTimer.async_wait([](const boost::system::error_code& ecode) {
        Daemon.running = 0; 
    });
}

void I2PControlSession::handleShutdownGraceful(Response& response)
{
    i2p::context.SetAcceptsTunnels(false);
    int timeout = i2p::tunnel::tunnels.GetTransitTunnelsExpirationTimeout();
    LogPrint(eLogInfo, "Graceful shutdown requested. Will shutdown after ", timeout, " seconds");
    response.setParam(I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN_GRACEFUL, "");
    shutdownTimer.expires_from_now(boost::posix_time::seconds(timeout + 1));
    shutdownTimer.async_wait([](const boost::system::error_code& ecode) {
        Daemon.running = 0; 
    });
}

void I2PControlSession::handleReseed(Response& response)
{
    LogPrint(eLogInfo, "Reseed requested");
    response.setParam(I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN, ""); 
    i2p::data::netdb.Reseed();
}

void I2PControlSession::expireTokens(const boost::system::error_code& error)
{
    if(error == boost::asio::error::operation_aborted)
        return; // Do not restart timer, shutting down

    startExpireTokensJob();
    LogPrint(eLogDebug, "I2PControl is expiring tokens.");
    const uint64_t now = util::GetSecondsSinceEpoch();
    std::lock_guard<std::mutex> lock(tokensMutex);
    for(auto it = tokens.begin(); it != tokens.end(); ) {
        if(now - it->second > I2P_CONTROL_TOKEN_LIFETIME)
            it = tokens.erase(it);
        else
            ++it;
    }
}

void I2PControlSession::startExpireTokensJob()
{
    expireTokensTimer.expires_from_now(boost::posix_time::seconds(I2P_CONTROL_TOKEN_LIFETIME));
    expireTokensTimer.async_wait(std::bind(
        &I2PControlSession::expireTokens, shared_from_this(), std::placeholders::_1
    ));
}

}
}
