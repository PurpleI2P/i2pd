/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <thread>
#include <clocale>
#include "Config.h"
#include "Daemon.h"
#include "util.h"
#include "Log.h"

#ifdef _WIN32
#ifdef WIN32_APP
#include <windows.h>
#include "Win32App.h"
#endif

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
		setlocale(LC_TIME, "C");

		i2p::log::SetThrowFunction ([](const std::string& s)
			{
				MessageBox(0, TEXT(s.c_str ()), TEXT("i2pd"), MB_ICONERROR | MB_TASKMODAL | MB_OK );
			}
		);

		if (!Daemon_Singleton::init(argc, argv))
			return false;
		return true;
	}

	bool DaemonWin32::start()
	{
		setlocale(LC_CTYPE, "");
		SetConsoleCP(1251);
		SetConsoleOutputCP(1251);
		setlocale(LC_ALL, "Russian");
		setlocale(LC_TIME, "C");
#ifdef WIN32_APP
		if (!i2p::win32::StartWin32App ()) return false;
#endif
		bool ret = Daemon_Singleton::start();
		if (ret && i2p::log::Logger().GetLogType() == eLogFile)
		{
			// TODO: find out where this garbage to console comes from
			SetStdHandle(STD_OUTPUT_HANDLE, INVALID_HANDLE_VALUE);
			SetStdHandle(STD_ERROR_HANDLE, INVALID_HANDLE_VALUE);
		}
		bool insomnia; i2p::config::GetOption("insomnia", insomnia);
		if (insomnia)
			SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
		return ret;
	}

	bool DaemonWin32::stop()
	{
#ifdef WIN32_APP
		i2p::win32::StopWin32App ();
#endif
		return Daemon_Singleton::stop();
	}

	void DaemonWin32::run ()
	{
#ifdef WIN32_APP
		i2p::win32::RunWin32App ();
#else
		while (running)
		{
			std::this_thread::sleep_for (std::chrono::seconds(1));
		}
#endif
	}
}
}
#endif //_WIN32
