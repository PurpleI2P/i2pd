#include <boost/bind.hpp>
#include <ctime>
#include <fstream>
#include "util/Log.h"
#include "util/util.h"
#include "util/I2PEndian.h"
#include "HTTPServer.h"

namespace i2p {
namespace util {

HTTPConnection::HTTPConnection(boost::asio::ip::tcp::socket* socket,
 std::shared_ptr<client::i2pcontrol::I2PControlSession> session)
    : m_Socket(socket), m_BufferLen(0), m_Request(), m_Reply(), m_Session(session)
{
    
}

void HTTPConnection::Terminate()
{
    m_Socket->close();
}

void HTTPConnection::Receive()
{
    m_Socket->async_read_some(
        boost::asio::buffer(m_Buffer, HTTP_CONNECTION_BUFFER_SIZE), std::bind(
            &HTTPConnection::HandleReceive, shared_from_this(),
            std::placeholders::_1, std::placeholders::_2
        )
    );
}

void HTTPConnection::HandleReceive(const boost::system::error_code& e, std::size_t nb_bytes)
{
    if(!e) {
        m_Buffer[nb_bytes] = 0;
        m_BufferLen = nb_bytes;
        const std::string data = std::string(m_Buffer, m_Buffer + m_BufferLen);
        if(!m_Request.hasData()) // New request
            m_Request = i2p::util::http::Request(data);
        else 
            m_Request.update(data);

        if(m_Request.isComplete()) {
            RunRequest();
            m_Request.clear();
        } else {
            Receive();
        }
    } else if(e != boost::asio::error::operation_aborted)
        Terminate();
}

void HTTPConnection::RunRequest()
{
    try {
      if(m_Request.getMethod() == "GET")
          return HandleRequest();
      if(m_Request.getHeader("Content-Type").find("application/json") != std::string::npos)
          return HandleI2PControlRequest();
    } catch(...) {
        // Ignore the error for now, probably Content-Type doesn't exist
        // Could also be invalid json data
    }
    // Unsupported method
    m_Reply = i2p::util::http::Response(502, "");
    SendReply();
}

void HTTPConnection::ExtractParams(const std::string& str, std::map<std::string, std::string>& params)
{
    if(str[0] != '&') return;
    size_t pos = 1, end;
    do
    {
        end = str.find('&', pos);
        std::string param = str.substr(pos, end - pos);
        LogPrint(param);
        size_t e = param.find('=');
        if(e != std::string::npos)
            params[param.substr(0, e)] = param.substr(e+1);
        pos = end + 1;
    }   
    while(end != std::string::npos);
}

void HTTPConnection::HandleWriteReply(const boost::system::error_code& e)
{
    if(e != boost::asio::error::operation_aborted) {
        boost::system::error_code ignored_ec;
        m_Socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
        Terminate();
    }
}

void HTTPConnection::Send404Reply()
{
    try {
        const std::string error_page = "404.html";
        m_Reply = i2p::util::http::Response(404, GetFileContents(error_page, true));
        m_Reply.setHeader("Content-Type", i2p::util::http::getMimeType(error_page));
    } catch(const std::runtime_error&) {
        // Failed to load 404.html, assume the webui is incorrectly installed
        m_Reply = i2p::util::http::Response(404,
            "<!DOCTYPE HTML><html>"
            "<head><title>Error: 404 - webui not installed</title></head><body>"
                "<p>It looks like your webui installation is broken.</p>"
                "<p>Run the following command to (re)install it:</p>"
                "<pre>./i2pd --install=/path/to/webui</pre>"
                "<p>Or from a directory containing a folder named webui:</p>"
                "<pre>./i2pd --install</pre>"
                "<p>The webui folder should come with the binaries.</p>"
            "</body></html>"
        );
    }
    SendReply();
}

std::string HTTPConnection::GetFileContents(const std::string& filename, bool preprocess) const
{
    boost::system::error_code e;

     // Use canonical to avoid .. or . in path
    const boost::filesystem::path address = boost::filesystem::canonical(
        i2p::util::filesystem::GetWebuiDataDir() / filename, e
    );

    const std::string address_str = address.string();
    
    std::ifstream ifs(address_str, std::ios_base::in | std::ios_base::binary);
    if(e || !ifs || !isAllowed(address_str))
        throw std::runtime_error("Cannot load " + address_str + ".");

    std::string str;
    ifs.seekg(0, ifs.end);
    str.resize(ifs.tellg());
    ifs.seekg(0, ifs.beg);
    ifs.read(&str[0], str.size());
    ifs.close();
    
    if(preprocess)
        return i2p::util::http::preprocessContent(str, address.parent_path().string());
    else
        return str;
}

void HTTPConnection::HandleRequest()
{

    std::string uri = m_Request.getUri();
    if(uri == "/")
        uri = "index.html";

    try {
        m_Reply = i2p::util::http::Response(200, GetFileContents(uri, true));
        m_Reply.setHeader("Content-Type", i2p::util::http::getMimeType(uri) + "; charset=UTF-8");
        SendReply();
    } catch(const std::runtime_error&) {
        // Cannot open the file for some reason, send 404
        Send404Reply();
    }
}

void HTTPConnection::HandleI2PControlRequest()
{
    std::stringstream ss(m_Request.getContent());
    const client::i2pcontrol::I2PControlSession::Response rsp = m_Session->handleRequest(ss);
    m_Reply = i2p::util::http::Response(200, rsp.toJsonString());
    m_Reply.setHeader("Content-Type", "application/json");
    SendReply();
}

bool HTTPConnection::isAllowed(const std::string& address) const
{
    const std::size_t pos_dot = address.find_last_of('.');
    const std::size_t pos_slash = address.find_last_of('/');
    if(pos_dot == std::string::npos || pos_dot == address.size() - 1)
        return false;
    if(pos_slash != std::string::npos && pos_dot < pos_slash)
        return false;
    return true;
}

void HTTPConnection::SendReply()
{
    // we need the date header to be compliant with HTTP 1.1
    std::time_t time_now = std::time(nullptr);
    char time_buff[128];
    if(std::strftime(time_buff, sizeof(time_buff), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&time_now)) ) {
        m_Reply.setHeader("Date", std::string(time_buff));
        m_Reply.setContentLength();
    }
    boost::asio::async_write(
        *m_Socket, boost::asio::buffer(m_Reply.toString()),
        std::bind(&HTTPConnection::HandleWriteReply, shared_from_this(), std::placeholders::_1)
    );
}

HTTPServer::HTTPServer(const std::string& address, int port):
    m_Thread(nullptr), m_Work(m_Service),
    m_Acceptor(m_Service, boost::asio::ip::tcp::endpoint(
        boost::asio::ip::address::from_string(address), port)
    ),
    m_NewSocket(nullptr),
    m_Session(std::make_shared<client::i2pcontrol::I2PControlSession>(m_Service))
{

}

HTTPServer::~HTTPServer()
{
    Stop();
}

void HTTPServer::Start()
{
    m_Thread = new std::thread(std::bind(&HTTPServer::Run, this));
    m_Acceptor.listen();
    m_Session->start();
    Accept();
}

void HTTPServer::Stop()
{
    m_Session->stop();
    m_Acceptor.close();
    m_Service.stop();
    if(m_Thread)
    {
        m_Thread->join();
        delete m_Thread;
        m_Thread = nullptr;
    }
}

void HTTPServer::Run()
{
    m_Service.run();
}

void HTTPServer::Accept()
{
    m_NewSocket = new boost::asio::ip::tcp::socket(m_Service);
    m_Acceptor.async_accept(*m_NewSocket, boost::bind(&HTTPServer::HandleAccept, this,
        boost::asio::placeholders::error));
}

void HTTPServer::HandleAccept(const boost::system::error_code& ecode)
{
    if(!ecode) {
        CreateConnection(m_NewSocket);
        Accept();
    }
}

void HTTPServer::CreateConnection(boost::asio::ip::tcp::socket* m_NewSocket)
{
    auto conn = std::make_shared<HTTPConnection>(m_NewSocket, m_Session);
    conn->Receive();
}

}
}
