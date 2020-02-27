#include "WebSocks.h"
#include "Log.h"
#include <string>

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
			LogPrint(eLogInfo, "[Tunnels] starting websocks tunnel at %s:%d is rejected: WebSockets is deprecated", m_Addr, m_Port);
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

