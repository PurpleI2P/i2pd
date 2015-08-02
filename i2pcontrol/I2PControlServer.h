#ifndef I2P_CONTROL_SERVER_H__
#define I2P_CONTROL_SERVER_H__

#include "I2PControl.h"
#include <inttypes.h>
#include <thread>
#include <memory>
#include <array>
#include <string>
#include <sstream>
#include <map>
#include <set>
#include <boost/asio.hpp>

namespace i2p {
namespace client {

const size_t I2P_CONTROL_MAX_REQUEST_SIZE = 1024;
typedef std::array<char, I2P_CONTROL_MAX_REQUEST_SIZE> I2PControlBuffer;        

class I2PControlService {
public:

    I2PControlService(const std::string& address, int port, const std::string& pass);
    ~I2PControlService ();

    void Start ();
    void Stop ();

private:

    void Run ();
    void Accept ();
    void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket);    
    void ReadRequest (std::shared_ptr<boost::asio::ip::tcp::socket> socket);
    void HandleRequestReceived (const boost::system::error_code& ecode, size_t bytes_transferred, 
        std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<I2PControlBuffer> buf);
    void SendResponse (std::shared_ptr<boost::asio::ip::tcp::socket> socket,
        std::shared_ptr<I2PControlBuffer> buf, const std::string& response, bool isHtml);
    void HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
        std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<I2PControlBuffer> buf);

private:

    bool m_IsRunning;
    std::thread * m_Thread; 

    boost::asio::io_service m_Service;
    boost::asio::ip::tcp::acceptor m_Acceptor;

    std::shared_ptr<I2PControlSession> m_Session;
    
};
}
}

#endif

