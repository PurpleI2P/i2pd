#ifndef WIN32APP_H__
#define WIN32APP_H__

#define DOTNET_WIN32_CLASSNAME "dotnet main window"

namespace dotnet
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
