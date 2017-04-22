#ifdef USE_UPNP
#include <string>
#include <thread>

#include <boost/thread/thread.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "Log.h"

#include "RouterContext.h"
#include "UPnP.h"
#include "NetDb.hpp"
#include "util.h"
#include "RouterInfo.h"
#include "Config.h"

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

namespace i2p
{
namespace transport
{
	UPnP::UPnP () : m_IsRunning(false), m_Thread (nullptr), m_Timer (m_Service)
	{
	}

	void UPnP::Stop ()
	{
		if (m_IsRunning)
		{
			LogPrint(eLogInfo, "UPnP: stopping");
			m_IsRunning = false;
			m_Timer.cancel ();
			m_Service.stop ();
			if (m_Thread)
			{
				m_Thread->join ();
				m_Thread.reset (nullptr);
			}
			CloseMapping ();
			Close ();
		}
	}

	void UPnP::Start()
	{
		m_IsRunning = true;
		LogPrint(eLogInfo, "UPnP: starting");
		m_Service.post (std::bind (&UPnP::Discover, this));
		std::unique_lock<std::mutex> l(m_StartedMutex);
		m_Thread.reset (new std::thread (std::bind (&UPnP::Run, this)));
		m_Started.wait_for (l, std::chrono::seconds (5)); // 5 seconds maximum
	}

	UPnP::~UPnP ()
	{
		Stop ();
	}

	void UPnP::Run ()
	{
		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
				// Discover failed
				break; // terminate the thread
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "UPnP: runtime exception: ", ex.what ());
				PortMapping ();
			}
		}
	}

	void UPnP::Discover ()
	{
		int nerror = 0;
#if MINIUPNPC_API_VERSION >= 14
		m_Devlist = upnpDiscover (2000, m_MulticastIf, m_Minissdpdpath, 0, 0, 2, &nerror);
#else
		m_Devlist = upnpDiscover (2000, m_MulticastIf, m_Minissdpdpath, 0, 0, &nerror);
#endif
		{
			// notify satrting thread
			std::unique_lock<std::mutex> l(m_StartedMutex);
			m_Started.notify_all ();
		}

		int r;
		r = UPNP_GetValidIGD (m_Devlist, &m_upnpUrls, &m_upnpData, m_NetworkAddr, sizeof (m_NetworkAddr));
		if (r == 1)
		{
			r = UPNP_GetExternalIPAddress (m_upnpUrls.controlURL, m_upnpData.first.servicetype, m_externalIPAddress);
			if(r != UPNPCOMMAND_SUCCESS)
			{
				LogPrint (eLogError, "UPnP: UPNP_GetExternalIPAddress() returned ", r);
				return;
			}
			else
			{
				if (!m_externalIPAddress[0])
				{
					LogPrint (eLogError, "UPnP: GetExternalIPAddress() failed.");
					return;
				}
			}
		}
		else
		{
			LogPrint (eLogError, "UPnP: GetValidIGD() failed.");
			return;
		}

		// UPnP discovered
		LogPrint (eLogDebug, "UPnP: ExternalIPAddress is ", m_externalIPAddress);
		i2p::context.UpdateAddress (boost::asio::ip::address::from_string (m_externalIPAddress));
		// port mapping
		PortMapping ();
	}

	void UPnP::PortMapping ()
	{
		const auto& a = context.GetRouterInfo().GetAddresses();
		for (const auto& address : a)
		{
			if (!address->host.is_v6 ())
			TryPortMapping (address);
		}
		m_Timer.expires_from_now (boost::posix_time::minutes(20));	// every 20 minutes
		m_Timer.async_wait ([this](const boost::system::error_code& ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
			PortMapping ();
		});

	}

	void UPnP::CloseMapping ()
	{
		const auto& a = context.GetRouterInfo().GetAddresses();
		for (const auto& address : a)
		{
			if (!address->host.is_v6 ())
			CloseMapping (address);
		}
	}

	void UPnP::TryPortMapping (std::shared_ptr<i2p::data::RouterInfo::Address> address)
	{
		std::string strType (GetProto (address)), strPort (std::to_string (address->port));
		int r;
		std::string strDesc; i2p::config::GetOption("upnp.name", strDesc);
		r = UPNP_AddPortMapping (m_upnpUrls.controlURL, m_upnpData.first.servicetype, strPort.c_str (), strPort.c_str (), m_NetworkAddr, strDesc.c_str (), strType.c_str (), 0, "0");
		if (r!=UPNPCOMMAND_SUCCESS)
		{
			LogPrint (eLogError, "UPnP: AddPortMapping (", m_NetworkAddr, ":", strPort, ") failed with code ", r);
			return;
		}
		else
		{
			LogPrint (eLogDebug, "UPnP: Port Mapping successful. (", m_NetworkAddr ,":", strPort, " type ", strType, " -> ", m_externalIPAddress ,":", strPort ,")");
			return;
		}
	}

	void UPnP::CloseMapping (std::shared_ptr<i2p::data::RouterInfo::Address> address)
	{
		std::string strType (GetProto (address)), strPort (std::to_string (address->port));
		int r = 0;
		r = UPNP_DeletePortMapping (m_upnpUrls.controlURL, m_upnpData.first.servicetype, strPort.c_str (), strType.c_str (), 0);
		LogPrint (eLogError, "UPnP: DeletePortMapping() returned : ", r);
	}

	void UPnP::Close ()
	{
		freeUPNPDevlist (m_Devlist);
		m_Devlist = 0;
		FreeUPNPUrls (&m_upnpUrls);
	}

	std::string UPnP::GetProto (std::shared_ptr<i2p::data::RouterInfo::Address> address)
	{
		switch (address->transportStyle)
		{
			case i2p::data::RouterInfo::eTransportNTCP:
			return "TCP";
			break;
			case i2p::data::RouterInfo::eTransportSSU:
			default:
			return "UDP";
		}
	}
}
}
#else /* USE_UPNP */
namespace i2p {
namespace transport {
}
}
#endif /* USE_UPNP */
