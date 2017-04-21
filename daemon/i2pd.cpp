#include <stdlib.h>
#include "Daemon.h"

#if defined(QT_GUI_LIB)

namespace i2p
{
namespace qt
{
    int RunQT (int argc, char* argv[]);
}
}
int main( int argc, char* argv[] )
{
    return i2p::qt::RunQT (argc, argv);
}

#else
int main( int argc, char* argv[] )
{
    if (Daemon.init(argc, argv))
	{
		if (Daemon.start())
			Daemon.run ();
		Daemon.stop();
	}
	return EXIT_SUCCESS;
}
#endif

#ifdef _WIN32
#include <windows.h>

int CALLBACK WinMain(
	_In_ HINSTANCE hInstance,
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR     lpCmdLine,
	_In_ int       nCmdShow
	)
{
	return main(__argc, __argv);
}
#endif
