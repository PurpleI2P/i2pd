#include <boost/filesystem.hpp>

#include "util.h"
#include "Daemon.h"

int main( int argc, char* argv[] )
{
	i2p::util::config::OptionParser(argc, argv);

	LogPrint("\n\n\n\ni2pd starting\n");
	LogPrint("data directory: ", i2p::util::filesystem::GetDataDir().string());
	i2p::util::filesystem::ReadConfigFile(i2p::util::config::mapArgs, i2p::util::config::mapMultiArgs);

	Daemon.start();
	while (Daemon.running)
	{
		//TODO Meeh: Find something better to do here.
		std::this_thread::sleep_for (std::chrono::seconds(1));
	}
	Daemon.stop();

	return 0;
}
