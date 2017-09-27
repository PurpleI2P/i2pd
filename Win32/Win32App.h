#ifndef WIN32APP_H__
#define WIN32APP_H__

#define I2PD_WIN32_CLASSNAME "i2pd main window"

namespace i2p
{
namespace win32
{
	bool StartWin32App ();
	void StopWin32App ();
	int RunWin32App ();
	bool GracefulShutdown ();
	bool StopGracefulShutdown ();
}
}
#endif // WIN32APP_H__
