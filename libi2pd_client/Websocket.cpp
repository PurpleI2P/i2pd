#ifdef WITH_EVENTS
#include "Websocket.h"
#include "Log.h"

#include <set>
#include <functional>

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

			WebsocketServerImpl(const std::string & addr, int port) :
				m_run(false),
				m_ws_thread(nullptr),
				m_ev_thread(nullptr),
				m_WebsocketTicker(m_Service)
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
				m_ws_thread = new std::thread([&] () {
						while(m_run) {
							try {
								m_server.run();
							} catch (std::exception & e ) {
								LogPrint(eLogError, "Websocket server: ", e.what());
							}
						}
					});
				m_ev_thread = new std::thread([&] () {
						while(m_run) {
							try {
								m_Service.run();
								break;
							} catch (std::exception & e ) {
								LogPrint(eLogError, "Websocket service: ", e.what());
							}
						}
					});
				ScheduleTick();
			}

			void Stop() {
				m_run = false;
				m_Service.stop();
				m_server.stop();

				if(m_ev_thread) {
					m_ev_thread->join();
					delete m_ev_thread;
				}
				m_ev_thread = nullptr;

				if(m_ws_thread) {
					m_ws_thread->join();
					delete m_ws_thread;
				}
				m_ws_thread = nullptr;
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

			void HandleTick(const boost::system::error_code & ec)
			{

				if(ec != boost::asio::error::operation_aborted)
					LogPrint(eLogError, "Websocket ticker: ", ec.message());
				// pump collected events to us
				i2p::event::core.PumpCollected(this);
				ScheduleTick();
			}

			void ScheduleTick()
			{
				LogPrint(eLogDebug, "Websocket schedule tick");
				boost::posix_time::seconds dlt(1);
				m_WebsocketTicker.expires_from_now(dlt);
				m_WebsocketTicker.async_wait(std::bind(&WebsocketServerImpl::HandleTick, this, std::placeholders::_1));
			}

			/** @brief called from m_ev_thread */
			void HandlePumpEvent(const EventType & ev, const uint64_t & val)
			{
				EventType e;
				for (const auto & i : ev)
					e[i.first] = i.second;

				e["number"] = std::to_string(val);
				HandleEvent(e);
			}

			/** @brief called from m_ws_thread */
			void HandleEvent(const EventType & ev)
			{
				std::lock_guard<std::mutex> lock(m_connsMutex);
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
			std::thread * m_ws_thread;
			std::thread * m_ev_thread;
			std::mutex m_connsMutex;
			ConnList m_conns;
			ServerImpl m_server;
			boost::asio::io_service m_Service;
			boost::asio::deadline_timer m_WebsocketTicker;
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
#endif
