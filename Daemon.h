#pragma once

#include "HTTPServer.h"
#include "HTTPProxy.h"

namespace i2p
{
	namespace util
	{
		class Daemon_Singleton
		{
		public:
			virtual bool start();
			virtual bool stop();

			int isLogging;
			int isDaemon;
			
			int running = 1;

		private:
			i2p::util::HTTPServer *httpServer;
			i2p::proxy::HTTPProxy *httpProxy;

		protected:
			Daemon_Singleton() : running(1) {};
			virtual ~Daemon_Singleton() {
				delete httpServer;
				delete httpProxy;
			};
		};

#ifdef _WIN32
		#define Daemon i2p::util::DaemonWin32::Instance()
		class DaemonWin32 : public Daemon_Singleton
		{
		public:
			static DaemonWin32& Instance()
			{
				static DaemonWin32 instance;
				return instance;
			}

			virtual bool start();
			virtual bool stop();
		};
#else
		#define Daemon i2p::util::DaemonLinux::Instance()
		class DaemonLinux : public Daemon_Singleton
		{
		public:
			static DaemonLinux& Instance()
			{
				static DaemonLinux instance;
				return instance;
			}

			virtual bool start();
			virtual bool stop();
                private:
                       std::string pidfile;
                       int pidFilehandle;

		};
#endif
	}
}
