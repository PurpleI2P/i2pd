#include "Daemon.h"

#ifdef _WIN32

#include "./Win32/Win32Service.h"


namespace i2p
{
	namespace util
	{
		bool DaemonWin32::start()
		{
			setlocale(LC_CTYPE, "");
			SetConsoleCP(1251);
			SetConsoleOutputCP(1251);
			setlocale(LC_ALL, "Russian");

			service_control(isDaemon);

			return Daemon_Singleton::start();
		}

		bool DaemonWin32::stop()
		{
			return Daemon_Singleton::stop();
		}
	}
}

#endif