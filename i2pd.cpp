#include <stdlib.h>
#include "Daemon.h"

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
