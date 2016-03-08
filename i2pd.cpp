#include <stdlib.h>
#include "Daemon.h"

int main( int argc, char* argv[] )
{
	Daemon.init(argc, argv);
	if (Daemon.start())
		Daemon.run ();
	Daemon.stop();
	return EXIT_SUCCESS;
}

