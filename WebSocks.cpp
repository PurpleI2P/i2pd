#include "WebSocks.h"
#include "Log.h"
#include <string>

#ifdef WITH_EVENTS
#include "ClientContext.h"
#include "Identity.h"
#include "Destination.h"
#include "Streaming.h"
#include <functional>

#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

#include <boost/property_tree/ini_parser.hpp>
#define GCC47_BOOST149 ((BOOST_VERSION == 104900) && (__GNUC__ == 4) && (__GNUC_MINOR__ >= 7))
#if !GCC47_BOOST149
#include <boost/property_tree/json_parser.hpp>
#endif

namespace i2p
{
namespace client
{
	typedef websocketpp::server<websocketpp::config::asio> WebSocksServerImpl;

	typedef std::function<void(std::shared_ptr<i2p::stream::Stream>)> StreamConnectFunc;


	struct IWebSocksConn : public I2PServiceHandler
	{
		IWebSocksConn(I2PService * parent) : I2PServiceHandler(parent) {}
		virtual void Close() = 0;
		virtual void GotMessage(const websocketpp::connection_hdl & conn, WebSocksServerImpl::message_ptr msg) = 0;
	};

	typedef std::shared_ptr<IWebSocksConn> WebSocksConn_ptr;

	WebSocksConn_ptr CreateWebSocksConn(const websocketpp::connection_hdl & conn, WebSocksImpl * parent);

	class WebSocksImpl
	{

		typedef std::mutex mutex_t;
		typedef std::unique_lock<mutex_t> lock_t;

		typedef std::shared_ptr<ClientDestination> Destination_t;
	public:

		typedef WebSocksServerImpl ServerImpl;
		typedef ServerImpl::message_ptr MessagePtr;

		WebSocksImpl(const std::string & addr, int port) :
			Parent(nullptr),
			m_Run(false),
			m_Addr(addr),
			m_Port(port),
			m_Thread(nullptr)
		{
			m_Server.init_asio();
			m_Server.set_open_handler(std::bind(&WebSocksImpl::ConnOpened, this, std::placeholders::_1));
		}

		void InitializeDestination(WebSocks * parent)
		{
			Parent = parent;
			m_Dest = Parent->GetLocalDestination();
		}

		ServerImpl::connection_ptr GetConn(const websocketpp::connection_hdl & conn)
		{
			return m_Server.get_con_from_hdl(conn);
		}

		void CloseConn(const websocketpp::connection_hdl & conn)
		{
			auto c = GetConn(conn);
			if(c) c->close(websocketpp::close::status::normal, "closed");
		}

		void CreateStreamTo(const std::string & addr, int port, StreamConnectFunc complete)
		{
			auto & addressbook = i2p::client::context.GetAddressBook();
			i2p::data::IdentHash ident;
			if(addressbook.GetIdentHash(addr, ident)) {
				// address found
				m_Dest->CreateStream(complete, ident, port);
			} else {
				// not found
				complete(nullptr);
			}
		}

		void ConnOpened(websocketpp::connection_hdl conn)
		{
			auto ptr = CreateWebSocksConn(conn, this);
			Parent->AddHandler(ptr);
			m_Conns.push_back(ptr);
		}

		void Start()
		{
			if(m_Run) return; // already started
			m_Server.listen(boost::asio::ip::address::from_string(m_Addr), m_Port);
			m_Server.start_accept();
			m_Run = true;
			m_Thread = new std::thread([&] (){
					while(m_Run) {
						try {
							m_Server.run();
						} catch( std::exception & ex) {
							LogPrint(eLogError, "Websocks runtime exception: ", ex.what());
						}
					}
			});
			m_Dest->Start();
		}

		void Stop()
		{
			for(const auto & conn : m_Conns)
				conn->Close();

			m_Dest->Stop();
			m_Run = false;
			m_Server.stop();
			if(m_Thread) {
				m_Thread->join();
				delete m_Thread;
			}
			m_Thread = nullptr;
		}

		boost::asio::ip::tcp::endpoint GetLocalEndpoint()
		{
			return boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(m_Addr), m_Port);
		}

		WebSocks * Parent;

	private:
		std::vector<WebSocksConn_ptr> m_Conns;
		bool m_Run;
		ServerImpl m_Server;
		std::string m_Addr;
		int m_Port;
		std::thread * m_Thread;
		Destination_t m_Dest;
	};

	struct WebSocksConn : public IWebSocksConn , public std::enable_shared_from_this<WebSocksConn>
	{
		enum ConnState
		{
			eWSCInitial,
			eWSCTryConnect,
			eWSCFailConnect,
			eWSCOkayConnect,
			eWSCClose,
			eWSCEnd
		};

		typedef WebSocksServerImpl ServerImpl;
		typedef ServerImpl::message_ptr Message_t;
		typedef websocketpp::connection_hdl ServerConn;
		typedef std::shared_ptr<ClientDestination> Destination_t;
		typedef std::shared_ptr<i2p::stream::StreamingDestination> StreamDest_t;
		typedef std::shared_ptr<i2p::stream::Stream> Stream_t;

		ServerConn m_Conn;
		Stream_t m_Stream;
		ConnState m_State;
		WebSocksImpl * m_Parent;
		std::string m_RemoteAddr;
		int m_RemotePort;
		uint8_t m_RecvBuf[2048];

		WebSocksConn(const ServerConn & conn, WebSocksImpl * parent) :
			IWebSocksConn(parent->Parent),
			m_Conn(conn),
			m_Stream(nullptr),
			m_State(eWSCInitial),
			m_Parent(parent)
		{

		}

		~WebSocksConn()
		{
			Close();
		}

		void EnterState(ConnState state)
		{
			LogPrint(eLogDebug, "websocks: state ", m_State, " -> ", state);
			switch(m_State)
			{
			case eWSCInitial:
				if (state == eWSCClose) {
					m_State = eWSCClose;
					// connection was opened but never used
					LogPrint(eLogInfo, "websocks: connection closed but never used");
					Close();
					return;
				} else if (state == eWSCTryConnect) {
					// we will try to connect
					m_State = eWSCTryConnect;
					m_Parent->CreateStreamTo(m_RemoteAddr, m_RemotePort, std::bind(&WebSocksConn::ConnectResult, this, std::placeholders::_1));
				} else {
					LogPrint(eLogWarning, "websocks: invalid state change ", m_State, " -> ", state);
				}
				return;
			case eWSCTryConnect:
				if(state == eWSCOkayConnect) {
					// we connected okay
					LogPrint(eLogDebug, "websocks: connected to ", m_RemoteAddr, ":", m_RemotePort);
					SendResponse("");
					m_State = eWSCOkayConnect;
				} else if(state == eWSCFailConnect) {
					// we did not connect okay
					LogPrint(eLogDebug, "websocks: failed to connect to ", m_RemoteAddr, ":", m_RemotePort);
					SendResponse("failed to connect");
					m_State = eWSCFailConnect;
					EnterState(eWSCInitial);
				} else if(state == eWSCClose) {
					// premature close
					LogPrint(eLogWarning, "websocks: websocket connection closed prematurely");
					m_State = eWSCClose;
				} else {
					LogPrint(eLogWarning, "websocks: invalid state change ", m_State, " -> ", state);
				}
				return;
			case eWSCFailConnect:
				if (state == eWSCInitial) {
					// reset to initial state so we can try connecting again
					m_RemoteAddr = "";
					m_RemotePort = 0;
					LogPrint(eLogDebug, "websocks: reset websocket conn to initial state");
					m_State = eWSCInitial;
				} else if (state == eWSCClose) {
					// we are going to close the connection
					m_State = eWSCClose;
					Close();
				} else {
					LogPrint(eLogWarning, "websocks: invalid state change ", m_State, " -> ", state);
				}
				return;
			case eWSCOkayConnect:
				if(state == eWSCClose) {
					// graceful close
					m_State = eWSCClose;
					Close();
				} else {
					LogPrint(eLogWarning, "websocks: invalid state change ", m_State, " -> ", state);
				}
			case eWSCClose:
				if(state == eWSCEnd) {
					LogPrint(eLogDebug, "websocks: socket ended");
					Kill();
					auto me = shared_from_this();
					Done(me);
				} else {
					LogPrint(eLogWarning, "websocks: invalid state change ", m_State, " -> ", state);
				}
				return;
			default:
				LogPrint(eLogError, "websocks: bad state ", m_State);
			}
		}

		void StartForwarding()
		{
			LogPrint(eLogDebug, "websocks: begin forwarding data");
			uint8_t b[1];
			m_Stream->Send(b, 0);
			AsyncRecv();
		}

		void HandleAsyncRecv(const boost::system::error_code &ec, std::size_t n)
		{
			if(ec) {
				// error
				LogPrint(eLogWarning, "websocks: connection error ", ec.message());
				EnterState(eWSCClose);
			} else {
				// forward data
				LogPrint(eLogDebug, "websocks recv ", n);
		
				std::string str((char*)m_RecvBuf, n);
				auto conn = m_Parent->GetConn(m_Conn);
				if(!conn)	 {
					LogPrint(eLogWarning, "websocks: connection is gone");
					EnterState(eWSCClose);
					return;
				}
				conn->send(str);
				AsyncRecv();
				
			}
		}

		void AsyncRecv()
		{
			m_Stream->AsyncReceive(
				boost::asio::buffer(m_RecvBuf, sizeof(m_RecvBuf)),
				std::bind(&WebSocksConn::HandleAsyncRecv, this, std::placeholders::_1, std::placeholders::_2), 60);
		}

		/** @brief send error message or empty string for success */
		void SendResponse(const std::string & errormsg)
		{
			boost::property_tree::ptree resp;
			if(errormsg.size()) {
				resp.put("error", errormsg);
				resp.put("success", 0);
			} else {
				resp.put("success", 1);
			}
			std::ostringstream ss;
			write_json(ss, resp);
			auto conn = m_Parent->GetConn(m_Conn);
			if(conn) conn->send(ss.str());
		}

		void ConnectResult(Stream_t stream)
		{
			m_Stream = stream;
			if(m_State == eWSCClose) {
				// premature close of websocket
				Close();
				return;
			}
			if(m_Stream) {
				// connect good
				EnterState(eWSCOkayConnect);
				StartForwarding();
			} else {
				// connect failed
				EnterState(eWSCFailConnect);
			}
		}
		
		virtual void GotMessage(const websocketpp::connection_hdl & conn, WebSocksServerImpl::message_ptr msg)
		{
			(void) conn;
			std::string payload = msg->get_payload();
			if(m_State == eWSCOkayConnect)
			{
				// forward to server
				LogPrint(eLogDebug, "websocks: forward ", payload.size());
				m_Stream->Send((uint8_t*)payload.c_str(), payload.size());
			} else if (m_State == eWSCInitial) {
				// recv connect request
				auto itr = payload.find(":");
				if(itr == std::string::npos) {
					// no port
					m_RemotePort = 0;
					m_RemoteAddr = payload;
				} else {
					// includes port
					m_RemotePort = std::stoi(payload.substr(itr+1));
					m_RemoteAddr = payload.substr(0, itr);
				}
				EnterState(eWSCTryConnect);
			} else {
				// wtf?
				LogPrint(eLogWarning, "websocks: got message in invalid state ", m_State);
			}
		}

		virtual void Close()
		{
			if(m_State == eWSCClose) {
				LogPrint(eLogDebug, "websocks: closing connection");
				if(m_Stream) m_Stream->Close();
				m_Parent->CloseConn(m_Conn);
				EnterState(eWSCEnd);
			} else {
				EnterState(eWSCClose);
			}
		}
	};

	WebSocksConn_ptr CreateWebSocksConn(const websocketpp::connection_hdl & conn, WebSocksImpl * parent)
	{
		auto ptr = std::make_shared<WebSocksConn>(conn, parent);
		auto c = parent->GetConn(conn);
		c->set_message_handler(std::bind(&WebSocksConn::GotMessage, ptr.get(), std::placeholders::_1, std::placeholders::_2));
		return ptr;
	}

}
}
#else

// no websocket support

namespace i2p
{
namespace client
{
	class WebSocksImpl
	{
	public:
		WebSocksImpl(const std::string & addr, int port) : m_Addr(addr), m_Port(port)
		{
		}

		~WebSocksImpl()
		{
		}

		void Start()
		{
			LogPrint(eLogInfo, "WebSockets not enabled on compile time");
		}

		void Stop()
		{
		}

		void InitializeDestination(WebSocks * parent)
		{
		}

		boost::asio::ip::tcp::endpoint GetLocalEndpoint()
		{
			return boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(m_Addr), m_Port);
		}

		std::string m_Addr;
		int m_Port;

	};
}
}

#endif
namespace i2p
{
namespace client
{
	WebSocks::WebSocks(const std::string & addr, int port, std::shared_ptr<ClientDestination> localDestination) : m_Impl(new WebSocksImpl(addr, port))
	{
		m_Impl->InitializeDestination(this);
	}
	WebSocks::~WebSocks() { delete m_Impl; }

	void WebSocks::Start()
	{
		m_Impl->Start();
		GetLocalDestination()->Start();
	}

	boost::asio::ip::tcp::endpoint WebSocks::GetLocalEndpoint() const
	{
		return m_Impl->GetLocalEndpoint();
	}

	void WebSocks::Stop()
	{
		m_Impl->Stop();
		GetLocalDestination()->Stop();
	}
}
}

