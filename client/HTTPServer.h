#ifndef HTTP_SERVER_H__
#define HTTP_SERVER_H__

#include <sstream>
#include <thread>
#include <memory>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include "i2pcontrol/I2PControl.h"
#include "util/HTTP.h"

namespace i2p {
namespace util {

const size_t HTTP_CONNECTION_BUFFER_SIZE = 8192;    
const int HTTP_DESTINATION_REQUEST_TIMEOUT = 10; // in seconds

class HTTPConnection: public std::enable_shared_from_this<HTTPConnection> {
public:

    HTTPConnection(boost::asio::ip::tcp::socket* socket,
        std::shared_ptr<i2p::client::i2pcontrol::I2PControlSession> session);

    ~HTTPConnection() { delete m_Socket; }
    void Receive();
    
private:

    void Terminate();
    void HandleReceive(const boost::system::error_code& ecode, std::size_t bytes_transferred);
    void RunRequest();
    void HandleWriteReply(const boost::system::error_code& ecode);
    void SendReply();

    void HandleRequest();
    void HandleI2PControlRequest();
    void ExtractParams(const std::string& str, std::map<std::string, std::string>& params);
    
    bool isAllowed(const std::string& address);
private:
    boost::asio::ip::tcp::socket* m_Socket;
    char m_Buffer[HTTP_CONNECTION_BUFFER_SIZE + 1];
    size_t m_BufferLen;
    util::http::Request m_Request;
    util::http::Response m_Reply;
    std::shared_ptr<i2p::client::i2pcontrol::I2PControlSession> m_Session;
};

class HTTPServer {
public:

    HTTPServer(const std::string& address, int port);
    virtual ~HTTPServer();

    void Start();
    void Stop();

private:

    void Run();
    void Accept();
    void HandleAccept(const boost::system::error_code& ecode);
    
private:

    std::thread * m_Thread;
    boost::asio::io_service m_Service;
    boost::asio::io_service::work m_Work;
    boost::asio::ip::tcp::acceptor m_Acceptor;
    boost::asio::ip::tcp::socket * m_NewSocket;
    std::shared_ptr<i2p::client::i2pcontrol::I2PControlSession> m_Session;

protected:
    void CreateConnection(boost::asio::ip::tcp::socket* m_NewSocket);
};
}
}

#endif


