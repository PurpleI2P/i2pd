#ifdef USE_UPNP
#include <string>
#include <thread>

#include <boost/thread/thread.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "Log.h"

#include "RouterContext.h"
#include "UPnP.h"
#include "NetDb.h"
#include "util.h"
#include "RouterInfo.h"

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

namespace i2p
{
namespace transport
{
    UPnP::UPnP () : m_Thread (nullptr)
    {
    }

    void UPnP::Stop ()
    {
        LogPrint(eLogInfo, "UPnP: stopping");
        if (m_Thread)
        {   
            m_Thread->join (); 
            delete m_Thread;
            m_Thread = nullptr;
        }
    }

    void UPnP::Start()
    {
        LogPrint(eLogInfo, "UPnP: starting");
        m_Thread = new std::thread (std::bind (&UPnP::Run, this));
    }
    
    UPnP::~UPnP ()
    {
    } 

    void UPnP::Run ()
    {
        const std::vector<std::shared_ptr<i2p::data::RouterInfo::Address> > a = context.GetRouterInfo().GetAddresses();
        for (auto address : a)
        {
            if (!address->host.is_v6 ())
            {
                Discover ();
                if (address->transportStyle == data::RouterInfo::eTransportSSU )
                {
                    TryPortMapping (I2P_UPNP_UDP, address->port);
                }
                else if (address->transportStyle == data::RouterInfo::eTransportNTCP )
                {
                    TryPortMapping (I2P_UPNP_TCP, address->port);
                }
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

        int r;
        r = UPNP_GetValidIGD (m_Devlist, &m_upnpUrls, &m_upnpData, m_NetworkAddr, sizeof (m_NetworkAddr));
        if (r == 1)
        {
            r = UPNP_GetExternalIPAddress (m_upnpUrls.controlURL, m_upnpData.first.servicetype, m_externalIPAddress);
            if(r != UPNPCOMMAND_SUCCESS)
            {
                LogPrint (eLogError, "UPnP: UPNP_GetExternalIPAddress () returned ", r);
                return;
            }
            else
            {
                if (m_externalIPAddress[0])
                {
                    LogPrint (eLogInfo, "UPnP: ExternalIPAddress = ", m_externalIPAddress);
                    i2p::context.UpdateAddress (boost::asio::ip::address::from_string (m_externalIPAddress));
                    return;
                }
                else
                {
                    LogPrint (eLogError, "UPnP: GetExternalIPAddress failed.");
                    return;
                }
            }
        }
    }

    void UPnP::TryPortMapping (int type, int port)
    {
        std::string strType, strPort (std::to_string (port));
        switch (type)
        {
            case I2P_UPNP_TCP:
                strType = "TCP";
                break;
            case I2P_UPNP_UDP:
            default:
                strType = "UDP";
        }
        int r;
        std::string strDesc = "I2Pd";
        try {
            for (;;) {
                r = UPNP_AddPortMapping (m_upnpUrls.controlURL, m_upnpData.first.servicetype, strPort.c_str (), strPort.c_str (), m_NetworkAddr, strDesc.c_str (), strType.c_str (), 0, "0");
                if (r!=UPNPCOMMAND_SUCCESS)
                {
                    LogPrint (eLogError, "UPnP: AddPortMapping (", strPort.c_str () ,", ", strPort.c_str () ,", ", m_NetworkAddr, ") failed with code ", r);
                    return;
                }
                else
                {
                    LogPrint (eLogDebug, "UPnP: Port Mapping successful. (", m_NetworkAddr ,":", strPort.c_str(), " type ", strType.c_str () ," -> ", m_externalIPAddress ,":", strPort.c_str() ,")");
                    return;
                }
                std::this_thread::sleep_for(std::chrono::minutes(20)); // c++11
                //boost::this_thread::sleep_for(); // pre c++11
                //sleep(20*60); // non-portable
            }
        }
        catch (boost::thread_interrupted)
        {
            CloseMapping(type, port);
            Close();
            throw;
        }
    }

    void UPnP::CloseMapping (int type, int port)
    {
        std::string strType, strPort (std::to_string (port));
        switch (type)
        {
            case I2P_UPNP_TCP:
                strType = "TCP";
                break;
            case I2P_UPNP_UDP:
            default:
                strType = "UDP";
        }
        int r = 0;
        r = UPNP_DeletePortMapping (m_upnpUrls.controlURL, m_upnpData.first.servicetype, strPort.c_str (), strType.c_str (), 0);
        LogPrint (eLogError, "UPnP: DeletePortMapping() returned : ", r, "\n");
    }

    void UPnP::Close ()
    {
        freeUPNPDevlist (m_Devlist);
        m_Devlist = 0;
        FreeUPNPUrls (&m_upnpUrls);
    }
}
}
#else /* USE_UPNP */
namespace i2p {
namespace transport {
}
}
#endif /* USE_UPNP */
