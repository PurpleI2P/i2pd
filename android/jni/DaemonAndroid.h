#ifndef DAEMON_H__
#define DAEMON_H__

#include <memory>
#include <string>

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
			virtual void run () {};

			bool isDaemon;
			bool running;

		protected:
			Daemon_Singleton();
			virtual ~Daemon_Singleton();

			bool IsService () const;

			// d-pointer for httpServer, httpProxy, etc.
			class Daemon_Singleton_Private;
			Daemon_Singleton_Private &d;
	};

#if defined(ANDROID)
#define Daemon i2p::util::DaemonAndroid::Instance()
	class DaemonAndroid : public Daemon_Singleton
	{
		public:
			static DaemonAndroid& Instance()
			{
				static DaemonAndroid instance;
				return instance;
			}

			bool start();
			bool stop();
			void run ();

		private:
			std::string pidfile;
			int pidFH;

		public:
			int gracefulShutdownInterval; // in seconds
	};
#endif
}
}

#endif // DAEMON_H__
