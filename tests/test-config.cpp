#include <cassert>
#include <string>

#include "Config.h"

int main ()
{
	char program[] = "test-config";
	char datadirOption[] = "--datadir=/tmp/i2pd-test";
	char * argv[] = { program, datadirOption };

	for (int i = 0; i < 2; i++)
	{
		i2p::config::Init ();
		i2p::config::ParseCmdline (2, argv);
		i2p::config::Finalize ();

		std::string datadir;
		assert (i2p::config::GetOption ("datadir", datadir));
		assert (datadir == "/tmp/i2pd-test");
	}

	return 0;
}
