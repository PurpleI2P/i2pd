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
namespace transport
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
		void TryPortMapping (int type, int port);
		void CloseMapping (int type, int port);
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
#ifndef _WIN32
        void *m_Module;
#else
        HINSTANCE m_Module;
#endif
	};
}
}

#endif // USE_UPNP
#endif // __UPNP_H__
