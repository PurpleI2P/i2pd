#include "I2PControlServer.h"
#include <sstream>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "util/Log.h"
#include "util/Timestamp.h"
#include "version.h"

namespace i2p
{
namespace client
{
    I2PControlService::I2PControlService(const std::string& address, int port)
        : m_Session(m_Service), m_IsRunning(false), m_Thread(nullptr),
          m_Acceptor(m_Service, boost::asio::ip::tcp::endpoint(
            boost::asio::ip::address::from_string(address), port)
          )
    {
    }

    I2PControlService::~I2PControlService ()
    {
        Stop ();
    }

    void I2PControlService::Start ()
    {
        if (!m_IsRunning)
        {
            Accept ();
            m_IsRunning = true;
            m_Thread = new std::thread (std::bind (&I2PControlService::Run, this));
        }
    }

    void I2PControlService::Stop ()
    {
        if (m_IsRunning)
        {
            m_IsRunning = false;
            m_Acceptor.cancel ();   
            m_Service.stop ();
            if (m_Thread)
            {   
                m_Thread->join (); 
                delete m_Thread;
                m_Thread = nullptr;
            }   
        }
    }

    void I2PControlService::Run () 
    { 
        while (m_IsRunning)
        {
            try
            {   
                m_Service.run ();
            }
            catch (std::exception& ex)
            {
                LogPrint (eLogError, "I2PControl: ", ex.what ());
            }   
        }   
    }

    void I2PControlService::Accept ()
    {
        auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (m_Service);
        m_Acceptor.async_accept (*newSocket, std::bind (&I2PControlService::HandleAccept, this,
            std::placeholders::_1, newSocket));
    }

    void I2PControlService::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket)
    {
        if (ecode != boost::asio::error::operation_aborted)
            Accept ();

        if (!ecode)
        {
            LogPrint (eLogInfo, "New I2PControl request from ", socket->remote_endpoint ());
            std::this_thread::sleep_for (std::chrono::milliseconds(5));
            ReadRequest (socket);   
        }
        else
            LogPrint (eLogError, "I2PControl accept error: ",  ecode.message ());
    }

    void I2PControlService::ReadRequest (std::shared_ptr<boost::asio::ip::tcp::socket> socket)
    {
        auto request = std::make_shared<I2PControlBuffer>();
        socket->async_read_some (
#if BOOST_VERSION >= 104900
            boost::asio::buffer (*request),  
#else
            boost::asio::buffer (request->data (), request->size ()), 
#endif              
            std::bind(&I2PControlService::HandleRequestReceived, this, 
            std::placeholders::_1, std::placeholders::_2, socket, request));
    }

    void I2PControlService::HandleRequestReceived (const boost::system::error_code& ecode,
        size_t bytes_transferred, std::shared_ptr<boost::asio::ip::tcp::socket> socket, 
        std::shared_ptr<I2PControlBuffer> buf)
    {
        if (ecode)
        {
            LogPrint (eLogError, "I2PControl read error: ", ecode.message ());
        }
        else
        {
            try
            {
                bool isHtml = !memcmp (buf->data (), "POST", 4);
                std::stringstream ss;
                ss.write (buf->data (), bytes_transferred);
                if (isHtml)
                {
                    std::string header;
                    while (!ss.eof () && header != "\r")
                        std::getline(ss, header);
                    if (ss.eof ())
                    {
                        LogPrint (eLogError, "Malformed I2PControl request. HTTP header expected");
                        return; // TODO:
                    }
                }

                I2PControlSession::Response response = m_Session.handleRequest(ss);
                SendResponse(socket, buf, response.toJsonString(), isHtml);
            }
            catch (const std::exception& ex)
            {
                LogPrint (eLogError, "I2PControl handle request: ", ex.what ());
            }
            catch (...)
            {
                LogPrint (eLogError, "I2PControl handle request unknown exception");
            }
        }
    }

    void I2PControlService::SendResponse (std::shared_ptr<boost::asio::ip::tcp::socket> socket,
        std::shared_ptr<I2PControlBuffer> buf, const std::string& response, bool isHtml)
    {
        size_t len = response.length (), offset = 0;
        if (isHtml)
        {
            std::ostringstream header;
            header << "HTTP/1.1 200 OK\r\n";
            header << "Connection: close\r\n";
            header << "Content-Length: " << boost::lexical_cast<std::string>(len) << "\r\n";
            header << "Content-Type: application/json\r\n";
            header << "Date: ";
            auto facet = new boost::local_time::local_time_facet ("%a, %d %b %Y %H:%M:%S GMT");
            header.imbue(std::locale (header.getloc(), facet));
            header << boost::posix_time::second_clock::local_time() << "\r\n"; 
            header << "\r\n";
            offset = header.str ().size ();
            memcpy (buf->data (), header.str ().c_str (), offset);
        }   
        memcpy (buf->data () + offset, response.c_str (), len);
        boost::asio::async_write (*socket, boost::asio::buffer (buf->data (), offset + len), 
            boost::asio::transfer_all (),
            std::bind(&I2PControlService::HandleResponseSent, this, 
                std::placeholders::_1, std::placeholders::_2, socket, buf));
    }

    void I2PControlService::HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
        std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<I2PControlBuffer> buf)
    {
        if (ecode)
            LogPrint (eLogError, "I2PControl write error: ", ecode.message ());
        socket->close ();
    }

}
}
