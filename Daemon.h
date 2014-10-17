#pragma once
#include <string>

#ifdef _WIN32
#define Daemon i2p::util::DaemonWin32::Instance()
#else
#define Daemon i2p::util::DaemonLinux::Instance()
#endif

namespace i2p
{
	namespace util
	{
		class Daemon_Singleton_Private;
		class Daemon_Singleton
		{
		public:
			virtual bool init(int argc, char* argv[]);
			virtual bool start();
			virtual bool stop();

			int isLogging;
			int isDaemon;
			
			int running;

		protected:
			Daemon_Singleton();
			virtual ~Daemon_Singleton();

			bool IsService () const;				

			// d-pointer for httpServer, httpProxy, etc.
			class Daemon_Singleton_Private;
			Daemon_Singleton_Private &d;
		};

#ifdef _WIN32
		class DaemonWin32 : public Daemon_Singleton
		{
		public:
			static DaemonWin32& Instance()
			{
				static DaemonWin32 instance;
				return instance;
			}

			virtual bool init(int argc, char* argv[]);
			virtual bool start();
			virtual bool stop();
		};
#else
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
