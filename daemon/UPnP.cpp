/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifdef USE_UPNP
#include <string>
#include <thread>

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
			LogPrint(eLogInfo, "UPnP: Stopping");
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
		LogPrint(eLogInfo, "UPnP: Starting");
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
		i2p::util::SetThreadName("UPnP");

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
				LogPrint (eLogError, "UPnP: Runtime exception: ", ex.what ());
				PortMapping ();
			}
		}
	}

	void UPnP::Discover ()
	{
		bool isError;
		int err;

#if ((MINIUPNPC_API_VERSION >= 8) || defined (UPNPDISCOVER_SUCCESS))
		err = UPNPDISCOVER_SUCCESS;

#if (MINIUPNPC_API_VERSION >= 14)
		m_Devlist = upnpDiscover (UPNP_RESPONSE_TIMEOUT, NULL, NULL, 0, 0, 2, &err);
#else
		m_Devlist = upnpDiscover (UPNP_RESPONSE_TIMEOUT, NULL, NULL, 0, 0, &err);
#endif

		isError = err != UPNPDISCOVER_SUCCESS;
#else // MINIUPNPC_API_VERSION >= 8
		err = 0;
		m_Devlist = upnpDiscover (UPNP_RESPONSE_TIMEOUT, NULL, NULL, 0);
		isError = m_Devlist == NULL;
#endif // MINIUPNPC_API_VERSION >= 8
		{
			// notify starting thread
			std::unique_lock<std::mutex> l(m_StartedMutex);
			m_Started.notify_all ();
		}

		if (isError)
		{
			LogPrint (eLogError, "UPnP: Unable to discover Internet Gateway Devices: error ", err);
			return;
		}

#if (MINIUPNPC_API_VERSION >= 18)
		err = UPNP_GetValidIGD (m_Devlist, &m_upnpUrls, &m_upnpData, m_NetworkAddr, sizeof (m_NetworkAddr),
					m_externalIPAddress, sizeof (m_externalIPAddress));
#else
		err = UPNP_GetValidIGD (m_Devlist, &m_upnpUrls, &m_upnpData, m_NetworkAddr, sizeof (m_NetworkAddr));
#endif
		m_upnpUrlsInitialized=err!=0;
		if (err == UPNP_IGD_VALID_CONNECTED)
		{
#if (MINIUPNPC_API_VERSION < 18)
			err = UPNP_GetExternalIPAddress (m_upnpUrls.controlURL, m_upnpData.first.servicetype, m_externalIPAddress);
			if(err != UPNPCOMMAND_SUCCESS)
			{
				LogPrint (eLogError, "UPnP: Unable to get external address: error ", err);
				return;
			}
			else
#endif
			{
				LogPrint (eLogError, "UPnP: Found Internet Gateway Device ", m_upnpUrls.controlURL);
				if (!m_externalIPAddress[0])
				{
					LogPrint (eLogError, "UPnP: Found Internet Gateway Device doesn't know our external address");
					return;
				}
			}
		}
		else
		{
			LogPrint (eLogError, "UPnP: Unable to find valid Internet Gateway Device: error ", err);
			return;
		}

		// UPnP discovered
		LogPrint (eLogDebug, "UPnP: ExternalIPAddress is ", m_externalIPAddress);
		i2p::context.UpdateAddress (boost::asio::ip::address::from_string (m_externalIPAddress));
		// port mapping
		PortMapping ();
	}

	int UPnP::CheckMapping (const char* port, const char* type)
	{
		int err = UPNPCOMMAND_SUCCESS;

#if (MINIUPNPC_API_VERSION >= 10)
		err = UPNP_GetSpecificPortMappingEntry(m_upnpUrls.controlURL, m_upnpData.first.servicetype, port, type, NULL, NULL, NULL, NULL, NULL, NULL);
#elif ((MINIUPNPC_API_VERSION >= 8) || defined (UPNPDISCOVER_SUCCESS))
		err = UPNP_GetSpecificPortMappingEntry(m_upnpUrls.controlURL, m_upnpData.first.servicetype, port, type, NULL, NULL, NULL, NULL, NULL);
#else
		err = UPNP_GetSpecificPortMappingEntry(m_upnpUrls.controlURL, m_upnpData.first.servicetype, port, type, NULL, NULL);
#endif
		return err;
	}

	void UPnP::PortMapping ()
	{
		auto a = context.GetRouterInfo().GetAddresses();
		if (!a) return;
		for (const auto& address : *a)
		{
			if (address && !address->host.is_v6 () && address->port)
				TryPortMapping (address);
		}
		m_Timer.expires_from_now (boost::posix_time::minutes(UPNP_PORT_FORWARDING_INTERVAL)); // every 20 minutes
		m_Timer.async_wait ([this](const boost::system::error_code& ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
				PortMapping ();
		});
	}

	void UPnP::TryPortMapping (std::shared_ptr<i2p::data::RouterInfo::Address> address)
	{
		std::string strType (GetProto (address)), strPort (std::to_string (address->port));
		std::string strDesc; i2p::config::GetOption("upnp.name", strDesc);
		int err = UPNPCOMMAND_SUCCESS;

		// check for existing mapping
		err = CheckMapping (strPort.c_str (), strType.c_str ());
		if (err != UPNPCOMMAND_SUCCESS) // if mapping not found
		{
			LogPrint (eLogDebug, "UPnP: Port ", strPort, " is possibly not forwarded: return code ", err);

#if ((MINIUPNPC_API_VERSION >= 8) || defined (UPNPDISCOVER_SUCCESS))
			err = UPNP_AddPortMapping (m_upnpUrls.controlURL, m_upnpData.first.servicetype, strPort.c_str (), strPort.c_str (), m_NetworkAddr, strDesc.c_str (), strType.c_str (), NULL, NULL);
#else
			err = UPNP_AddPortMapping (m_upnpUrls.controlURL, m_upnpData.first.servicetype, strPort.c_str (), strPort.c_str (), m_NetworkAddr, strDesc.c_str (), strType.c_str (), NULL);
#endif
			if (err != UPNPCOMMAND_SUCCESS)
			{
				LogPrint (eLogError, "UPnP: Port forwarding to ", m_NetworkAddr, ":", strPort, " failed: return code ", err);
				return;
			}
			else
			{
				LogPrint (eLogInfo, "UPnP: Port successfully forwarded (", m_externalIPAddress ,":", strPort, " type ", strType, " -> ", m_NetworkAddr ,":", strPort ,")");
				return;
			}
		}
		else
		{
			LogPrint (eLogDebug, "UPnP: External forward from ", m_NetworkAddr, ":", strPort, " exists on current Internet Gateway Device");
			return;
		}
	}

	void UPnP::CloseMapping ()
	{
		auto a = context.GetRouterInfo().GetAddresses();
		if (!a) return;
		for (const auto& address : *a)
		{
			if (address && !address->host.is_v6 () && address->port)
			CloseMapping (address);
		}
	}

	void UPnP::CloseMapping (std::shared_ptr<i2p::data::RouterInfo::Address> address)
	{
		if(!m_upnpUrlsInitialized) {
			return;
		}
		std::string strType (GetProto (address)), strPort (std::to_string (address->port));
		int err = UPNPCOMMAND_SUCCESS;

		err = CheckMapping (strPort.c_str (), strType.c_str ());
		if (err == UPNPCOMMAND_SUCCESS)
		{
			err = UPNP_DeletePortMapping (m_upnpUrls.controlURL, m_upnpData.first.servicetype, strPort.c_str (), strType.c_str (), NULL);
			LogPrint (eLogError, "UPnP: DeletePortMapping() returned : ", err);
		}
	}

	void UPnP::Close ()
	{
		freeUPNPDevlist (m_Devlist);
		m_Devlist = 0;
		if(m_upnpUrlsInitialized){
			FreeUPNPUrls (&m_upnpUrls);
			m_upnpUrlsInitialized=false;
		}
	}

	std::string UPnP::GetProto (std::shared_ptr<i2p::data::RouterInfo::Address> address)
	{
		switch (address->transportStyle)
		{
			case i2p::data::RouterInfo::eTransportNTCP2:
				return "TCP";
				break;
			case i2p::data::RouterInfo::eTransportSSU2:
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
