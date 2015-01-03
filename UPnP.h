#ifndef __UPNP_H__
#define __UPNP_H__

#ifdef USE_UPNP
#include <string>
#include <thread>

#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include <boost/asio.hpp>

#include "util.h"

#define I2P_UPNP_TCP 1
#define I2P_UPNP_UDP 2

namespace i2p
{
namespace UPnP
{
	class UPnP
	{
	public:

		UPnP ();
		~UPnP ();
        void Close ();

        void Start ();
        void Stop ();

		void Discover ();
		void TryPortMapping (int type);
		void CloseMapping (int type);
	private:
		void Run ();

        std::thread * m_Thread;
        struct UPNPUrls m_upnpUrls;
        struct IGDdatas m_upnpData;

        // For miniupnpc
        char * m_MulticastIf = 0;
        char * m_Minissdpdpath = 0;
        struct UPNPDev * m_Devlist = 0;
        char m_NetworkAddr[64];
        char m_externalIPAddress[40];
        bool m_IsModuleLoaded;
        std::string m_Port = std::to_string (util::config::GetArg ("-port", 17070));
#ifndef _WIN32
        void *m_Module;
#else
        HINSTANCE *m_Module;
#endif
	};
	extern UPnP upnpc;
}
}

#endif

#endif
