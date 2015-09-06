#ifndef HTTP_SERVER_H__
#define HTTP_SERVER_H__

#include <sstream>
#include <thread>
#include <memory>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include "util/HTTP.h"

namespace i2p {
namespace util {

const size_t HTTP_CONNECTION_BUFFER_SIZE = 8192;    
const int HTTP_DESTINATION_REQUEST_TIMEOUT = 10; // in seconds

class HTTPConnection: public std::enable_shared_from_this<HTTPConnection> {
public:

    HTTPConnection(boost::asio::ip::tcp::socket * socket)
        : m_Socket(socket), m_Timer(socket->get_io_service()), 
        m_BufferLen(0) {};
    ~HTTPConnection() { delete m_Socket; }
    void Receive();
    
private:

    void Terminate();
    void HandleReceive(const boost::system::error_code& ecode, std::size_t bytes_transferred);
    void RunRequest();
    void HandleWriteReply(const boost::system::error_code& ecode);
    void SendReply();

    void HandleRequest();
    void ExtractParams(const std::string& str, std::map<std::string, std::string>& params);
    
    bool isAllowed(const std::string& address);
private:
    boost::asio::ip::tcp::socket* m_Socket;
    boost::asio::deadline_timer m_Timer;
    char m_Buffer[HTTP_CONNECTION_BUFFER_SIZE + 1];
    char m_StreamBuffer[HTTP_CONNECTION_BUFFER_SIZE + 1];
    size_t m_BufferLen;
    util::http::Request m_Request;
    util::http::Response m_Reply;
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

protected:
    virtual void CreateConnection(boost::asio::ip::tcp::socket * m_NewSocket);
};
}
}

#endif


