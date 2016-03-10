#include "Config.h"
#include "Daemon.h"
#include "util.h"
#include "Log.h"

#ifdef _WIN32

#include "Win32/Win32App.h"

namespace i2p
{
	namespace util
	{
		bool DaemonWin32::init(int argc, char* argv[])
		{
			setlocale(LC_CTYPE, "");
			SetConsoleCP(1251);
			SetConsoleOutputCP(1251);
			setlocale(LC_ALL, "Russian");
            return Daemon_Singleton::init(argc, argv);
		}

		bool DaemonWin32::start()
		{
			setlocale(LC_CTYPE, "");
			SetConsoleCP(1251);
			SetConsoleOutputCP(1251);
			setlocale(LC_ALL, "Russian");
            if (!i2p::win32::StartWin32App ()) return false;

            // override log
            i2p::config::SetOption("log", std::string ("file"));
			bool ret = Daemon_Singleton::start();
			if (ret && IsLogToFile ())
			{
				// TODO: find out where this garbage to console comes from
				SetStdHandle(STD_OUTPUT_HANDLE, INVALID_HANDLE_VALUE);
				SetStdHandle(STD_ERROR_HANDLE, INVALID_HANDLE_VALUE);
			}
			return ret;
		}

		bool DaemonWin32::stop()
		{
		    i2p::win32::StopWin32App ();
			return Daemon_Singleton::stop();
		}

		void DaemonWin32::run ()
        {
            i2p::win32::RunWin32App ();
        }
	}
}

#endif
