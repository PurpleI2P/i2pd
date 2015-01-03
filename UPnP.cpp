#ifdef USE_UPNP
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#endif

#include <boost/thread/thread.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "Log.h"
#include "RouterContext.h"
#include "UPnP.h"
#include "NetDb.h"
#include "util.h"

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <dlfcn.h>

#ifndef UPNPDISCOVER_SUCCESS
/* miniupnpc 1.5 */
typedef UPNPDev* (*upnp_upnpDiscoverFunc) (int, const char *, const char *, int);
typedef int (*upnp_UPNP_AddPortMappingFunc) (const char *, const char *, const char *, const char *, 
                                             const char *, const char *, const char *, const char *);
#else
/* miniupnpc 1.6 */
typedef UPNPDev* (*upnp_upnpDiscoverFunc) (int, const char *, const char *, int, int, int *);
typedef int (*upnp_UPNP_AddPortMappingFunc) (const char *, const char *, const char *, const char *, 
                                             const char *, const char *, const char *, const char *, const char *);
#endif
typedef int (*upnp_UPNP_GetValidIGDFunc) (struct UPNPDev *, struct UPNPUrls *, struct IGDdatas *, char *, int);
typedef int (*upnp_UPNP_GetExternalIPAddressFunc) (const char *, const char *, char *);
typedef int (*upnp_UPNP_DeletePortMappingFunc) (const char *, const char *, const char *, const char *, const char *);
typedef void (*upnp_freeUPNPDevlistFunc) (struct UPNPDev *);
typedef void (*upnp_FreeUPNPUrlsFunc) (struct UPNPUrls *);

namespace i2p
{
namespace UPnP
{
    UPnP upnpc;

    UPnP::UPnP () : m_Thread (nullptr) , m_IsModuleLoaded (false)
    {
    }

    void UPnP::Stop ()
    {
        if (m_Thread)
        {   
            m_Thread->join (); 
            delete m_Thread;
            m_Thread = nullptr;
        }
    }

    void UPnP::Start()
    {
        m_Thread = new std::thread (std::bind (&UPnP::Run, this));
    }
    
    UPnP::~UPnP ()
    {
    } 

    void UPnP::Run ()
    {
#ifdef MAC_OSX
        m_Module = dlopen ("libminiupnpc.dylib", RTLD_LAZY);
#elif _WIN32
        m_Module = LoadLibrary ("libminiupnpc.dll");
        if (m_Module == NULL)
        {
            LogPrint ("Error loading UPNP library. This often happens if there is version mismatch!");
            return;
        }
        else
        {
            m_IsModuleLoaded = true;
        }
#else
        m_Module = dlopen ("libminiupnpc.so", RTLD_LAZY);
#endif
#ifndef _WIN32
        if (!m_Module)
        {
            LogPrint ("no UPnP module available (", dlerror (), ")");
            return;
        }
        else
        {
            m_IsModuleLoaded = true;
        }
#endif
        for (auto& address : context.GetRouterInfo ().GetAddresses ())
        {
            if (!address.host.is_v6 ())
            {
                m_Port = std::to_string (util::config::GetArg ("-port", address.port));
                Discover ();
                if (address.transportStyle == data::RouterInfo::eTransportSSU )
                {
                    TryPortMapping (I2P_UPNP_UDP);
                }
                else if (address.transportStyle == data::RouterInfo::eTransportNTCP )
                {
                    TryPortMapping (I2P_UPNP_TCP);
                }
            }
        }
    } 
        
    void UPnP::Discover ()
    {
        const char *error;
#ifdef _WIN32
        upnp_upnpDiscoverFunc upnpDiscoverFunc = (upnp_upnpDiscoverFunc) GetProcAddress (m_Module, "upnpDiscover");
#else
        upnp_upnpDiscoverFunc upnpDiscoverFunc = (upnp_upnpDiscoverFunc) dlsym (m_Module, "upnpDiscover");
        // reinterpret_cast<upnp_upnpDiscoverFunc> (dlsym(...));
        if ( (error = dlerror ()))
        {
            LogPrint ("Error loading UPNP library. This often happens if there is version mismatch!");
            return;
        }
#endif // _WIN32
#ifndef UPNPDISCOVER_SUCCESS
        /* miniupnpc 1.5 */
        m_Devlist = upnpDiscoverFunc (2000, m_MulticastIf, m_Minissdpdpath, 0);
#else
        /* miniupnpc 1.6 */
        int nerror = 0;
        m_Devlist = upnpDiscoverFunc (2000, m_MulticastIf, m_Minissdpdpath, 0, 0, &nerror);
#endif

        int r;
#ifdef _WIN32
        upnp_UPNP_GetValidIGDFunc UPNP_GetValidIGDFunc = (upnp_UPNP_GetValidIGDFunc) GetProcAddress (m_Module, "UPNP_GetValidIGD");
#else
        upnp_UPNP_GetValidIGDFunc UPNP_GetValidIGDFunc = (upnp_UPNP_GetValidIGDFunc) dlsym (m_Module, "UPNP_GetValidIGD");
#endif
        r = (*UPNP_GetValidIGDFunc) (m_Devlist, &m_upnpUrls, &m_upnpData, m_NetworkAddr, sizeof (m_NetworkAddr));
        if (r == 1)
        {
            upnp_UPNP_GetExternalIPAddressFunc UPNP_GetExternalIPAddressFunc = (upnp_UPNP_GetExternalIPAddressFunc) dlsym (m_Module, "UPNP_GetExternalIPAddress");
            r = UPNP_GetExternalIPAddressFunc (m_upnpUrls.controlURL, m_upnpData.first.servicetype, m_externalIPAddress);
            if(r != UPNPCOMMAND_SUCCESS)
            {
                LogPrint ("UPnP: UPNP_GetExternalIPAddress () returned ", r);
                return;
            }
            else
            {
                if (m_externalIPAddress[0])
                {
                    LogPrint ("UPnP: ExternalIPAddress = ", m_externalIPAddress);
                    i2p::context.UpdateAddress (boost::asio::ip::address::from_string (m_externalIPAddress));
                    return;
                }
                else
                {
                    LogPrint ("UPnP: GetExternalIPAddress failed.");
                    return;
                }
            }
        }
    }

    void UPnP::TryPortMapping (int type)
    {
        std::string strType;
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
#ifdef _WIN32
                upnp_UPNP_AddPortMappingFunc UPNP_AddPortMappingFunc = (upnp_UPNP_AddPortMappingFunc) GetProcAddress (m_Module, "UPNP_AddPortMapping");
#else
                upnp_UPNP_AddPortMappingFunc UPNP_AddPortMappingFunc = (upnp_UPNP_AddPortMappingFunc) dlsym (m_Module, "UPNP_AddPortMapping");
#endif
#ifndef UPNPDISCOVER_SUCCESS
                /* miniupnpc 1.5 */
                r = UPNP_AddPortMappingFunc (m_upnpUrls.controlURL, m_upnpData.first.servicetype, m_Port.c_str (), m_Port.c_str (), m_NetworkAddr, strDesc.c_str (), strType.c_str (), 0);
#else
                /* miniupnpc 1.6 */
                r = UPNP_AddPortMappingFunc (m_upnpUrls.controlURL, m_upnpData.first.servicetype, m_Port.c_str (), m_Port.c_str (), m_NetworkAddr, strDesc.c_str (), strType.c_str (), 0, "0");
#endif
                if (r!=UPNPCOMMAND_SUCCESS)
                {
                    LogPrint ("AddPortMapping (", m_Port.c_str () ,", ", m_Port.c_str () ,", ", m_NetworkAddr, ") failed with code ", r);
                    return;
                }
                else
                {
                    LogPrint ("UPnP Port Mapping successful. (", m_NetworkAddr ,":", m_Port.c_str(), " type ", strType.c_str () ," -> ", m_externalIPAddress ,":", m_Port.c_str() ,")");
                    return;
                }
                sleep(20*60);
            }
        }
        catch (boost::thread_interrupted)
        {
            CloseMapping(type);
            Close();
            throw;
        }
    }

    void UPnP::CloseMapping (int type)
    {
        std::string strType;
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
#ifdef _WIN32
        upnp_UPNP_DeletePortMappingFunc UPNP_DeletePortMappingFunc = (upnp_UPNP_DeletePortMappingFunc) GetProcAddress (m_Module, "UPNP_DeletePortMapping");
#else
        upnp_UPNP_DeletePortMappingFunc UPNP_DeletePortMappingFunc = (upnp_UPNP_DeletePortMappingFunc) dlsym (m_Module, "UPNP_DeletePortMapping");
#endif
        r = UPNP_DeletePortMappingFunc (m_upnpUrls.controlURL, m_upnpData.first.servicetype, m_Port.c_str (), strType.c_str (), 0);
        LogPrint ("UPNP_DeletePortMapping() returned : ", r, "\n");
    }

    void UPnP::Close ()
    {
#ifdef _WIN32
        upnp_freeUPNPDevlistFunc freeUPNPDevlistFunc = (upnp_freeUPNPDevlistFunc) GetProcAddress (m_Module, "freeUPNPDevlist");
#else
        upnp_freeUPNPDevlistFunc freeUPNPDevlistFunc = (upnp_freeUPNPDevlistFunc) dlsym (m_Module, "freeUPNPDevlist");
#endif
        freeUPNPDevlistFunc (m_Devlist);
        m_Devlist = 0;
#ifdef _WIN32
        upnp_FreeUPNPUrlsFunc FreeUPNPUrlsFunc = (upnp_FreeUPNPUrlsFunc) GetProcAddress (m_Module, "FreeUPNPUrlsFunc");
#else
        upnp_FreeUPNPUrlsFunc FreeUPNPUrlsFunc = (upnp_FreeUPNPUrlsFunc) dlsym (m_Module, "FreeUPNPUrlsFunc");
#endif
        FreeUPNPUrlsFunc (&m_upnpUrls);
#ifndef _WIN32
        dlclose (m_Module);
#else
        FreeLibrary (m_Module);
#endif
    }

}
}


#endif

