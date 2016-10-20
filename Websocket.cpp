#include "Websocket.h"
#include "Log.h"

#include <set>

#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <boost/property_tree/ini_parser.hpp>
#define GCC47_BOOST149 ((BOOST_VERSION == 104900) && (__GNUC__ == 4) && (__GNUC_MINOR__ >= 7))
#if !GCC47_BOOST149
#include <boost/property_tree/json_parser.hpp>
#endif

#include <stdexcept>

namespace i2p
{
  namespace event
  {

    typedef websocketpp::server<websocketpp::config::asio> ServerImpl;
    typedef websocketpp::connection_hdl ServerConn;
    
    class WebsocketServerImpl : public EventListener
    {
    private:
      typedef ServerImpl::message_ptr MessagePtr;
    public:

      WebsocketServerImpl(const std::string & addr, int port) : m_run(false), m_thread(nullptr)
      {
        m_server.init_asio();
        m_server.set_open_handler(std::bind(&WebsocketServerImpl::ConnOpened, this, std::placeholders::_1));
        m_server.set_close_handler(std::bind(&WebsocketServerImpl::ConnClosed, this, std::placeholders::_1));
        m_server.set_message_handler(std::bind(&WebsocketServerImpl::OnConnMessage, this, std::placeholders::_1, std::placeholders::_2));
        
        m_server.listen(boost::asio::ip::address::from_string(addr), port);
      }

      ~WebsocketServerImpl()
      {
      }
      
      void Start() {
        m_run = true;
        m_server.start_accept();
        m_thread = new std::thread([&] () {
            while(m_run) {
              try { 
                m_server.run();
              } catch (std::exception & e ) {
                LogPrint(eLogError, "Websocket server: ", e.what());
              }
            }
          });
      }

      void Stop() {
        m_run = false;
        m_server.stop();
        if(m_thread) {
          m_thread->join();
          delete m_thread;
        }
        m_thread = nullptr;
      }

      void ConnOpened(ServerConn c)
      {
        std::lock_guard<std::mutex> lock(m_connsMutex);
        m_conns.insert(c);
      }
      
      void ConnClosed(ServerConn c)
      {
        std::lock_guard<std::mutex> lock(m_connsMutex);
        m_conns.erase(c);
      }

      void OnConnMessage(ServerConn conn, ServerImpl::message_ptr msg)
      {
        (void) conn;
        (void) msg;
      }
      
      void HandleEvent(const EventType & ev)
      {
        std::lock_guard<std::mutex> lock(m_connsMutex);
        LogPrint(eLogDebug, "websocket event");
        boost::property_tree::ptree event;
        for (const auto & item : ev) {
          event.put(item.first, item.second);
        }
        std::ostringstream ss;
        write_json(ss, event);
        std::string s = ss.str();

         ConnList::iterator it;
         for (it = m_conns.begin(); it != m_conns.end(); ++it) {
           ServerImpl::connection_ptr con = m_server.get_con_from_hdl(*it);
           con->send(s);
         }
      }
      
    private:
      typedef std::set<ServerConn, std::owner_less<ServerConn> > ConnList;
      bool m_run;
      std::thread * m_thread;
      std::mutex m_connsMutex;
      ConnList m_conns;
      ServerImpl m_server;
    };


    WebsocketServer::WebsocketServer(const std::string & addr, int port) : m_impl(new WebsocketServerImpl(addr, port)) {}
    WebsocketServer::~WebsocketServer()
    {
      delete m_impl;
    }

    
    void WebsocketServer::Start()
    {
      m_impl->Start();
    }

    void WebsocketServer::Stop()
    {
      m_impl->Stop();
    }
    
    EventListener * WebsocketServer::ToListener()
    {
      return m_impl;
    }
  }
}
