#ifndef __UPNP_H__
#define __UPNP_H__

#ifdef USE_UPNP
#include <string>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <memory>

#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include <boost/asio.hpp>

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

	private:

		void Discover ();
		void PortMapping ();
		void TryPortMapping (std::shared_ptr<i2p::data::RouterInfo::Address> address);
		void CloseMapping ();
		void CloseMapping (std::shared_ptr<i2p::data::RouterInfo::Address> address);

		void Run ();
		std::string GetProto (std::shared_ptr<i2p::data::RouterInfo::Address> address);

	private:
	
		bool m_IsRunning;
        std::unique_ptr<std::thread> m_Thread;
		std::condition_variable m_Started;	
		std::mutex m_StartedMutex;	
		boost::asio::io_service m_Service;
		boost::asio::deadline_timer m_Timer;	
        struct UPNPUrls m_upnpUrls;
        struct IGDdatas m_upnpData;

        // For miniupnpc
        char * m_MulticastIf = 0;
        char * m_Minissdpdpath = 0;
        struct UPNPDev * m_Devlist = 0;
        char m_NetworkAddr[64];
        char m_externalIPAddress[40];
	};
}
}

#else  // USE_UPNP
namespace i2p {
namespace transport {
  /* class stub */
  class UPnP {
  public:
    UPnP () {};
    ~UPnP () {};
    void Start () { LogPrint(eLogWarning, "UPnP: this module was disabled at compile-time"); }
    void Stop () {};
  };
}
}
#endif // USE_UPNP
#endif // __UPNP_H__
