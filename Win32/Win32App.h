/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef WIN32APP_H__
#define WIN32APP_H__

#define I2PD_WIN32_CLASSNAME "i2pd main window"

namespace i2p
{
namespace win32
{
	extern DWORD g_GracefulShutdownEndtime;

	bool StartWin32App ();
	void StopWin32App ();
	int RunWin32App ();
	bool GracefulShutdown ();
	bool StopGracefulShutdown ();

	inline typedef std::function<void (bool)> DaemonSetIsGraceful;
	inline DaemonSetIsGraceful m_setIsGraceful;
	inline void SetIsGraceful (const DaemonSetIsGraceful& f) { m_setIsGraceful = f; };

	inline typedef std::function<bool ()> DaemonGetIsGraceful;
	inline DaemonGetIsGraceful m_getIsGraceful;
	inline void GetIsGraceful (const DaemonGetIsGraceful& f) { m_getIsGraceful = f; };

}
}
#endif // WIN32APP_H__
