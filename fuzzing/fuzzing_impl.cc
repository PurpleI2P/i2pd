

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <Config.h>
#include <Log.h>
#include <FS.h>
#include <Destination.h>
#include <NetDb.hpp>
#include <Tunnel.h>
#include <RouterContext.h>
#include <Transports.h>
#include <version.h>

#include "fuzzing.h"


static bool (*runner)(const uint8_t *, size_t);


static
bool
run_single(const uint8_t * data, size_t size)
{
	bool status;


	status = fuzzing_testinput(data, size);

	fuzzing_tick();
	fuzzing_throttle();

	return status;
}


static
bool
run_batch(const uint8_t * data, size_t size)
{
	bool status;
	size_t chunklen;


	if(size < 2)
	{
		// XXX - Test something to prevent fuzzer from giving up
		status = fuzzing_testinput(data, size);
		fuzzing_tick();
	}
	else
	{
		status = false;

		while(size >= 2)
		{
			chunklen = (data[0] << 8) | data[1];

			data += 2;
			size -= 2;

			if(chunklen > size)
				chunklen = size;

			if(fuzzing_testinput(data, chunklen))
				status = true;

			data += chunklen;
			size -= chunklen;

			fuzzing_tick();
		}
	}

	fuzzing_throttle();

	return status;
}


static
void
do_stop(void)
{
	i2p::tunnel::tunnels.Stop();
	i2p::transport::transports.Stop();
	i2p::data::netdb.Stop();
	i2p::log::Logger().Stop();
}


static
void
do_setup(void)
{
	i2p::log::Logger().Start();
	i2p::log::Logger().SetLogLevel("critical");

	i2p::config::Init();
	i2p::config::ParseCmdline(1, (char *[]) { (char *) "foo" });

	// Disable networking
	i2p::config::SetOption("ipv4", false);
	i2p::config::SetOption("ipv6", false);

	i2p::fs::DetectDataDir("testdata", false);
	i2p::fs::Init();

	i2p::context.SetNetID(I2PD_NET_ID);
	i2p::context.Init();

	i2p::data::netdb.Start();

	i2p::transport::transports.Start(true, true);

	i2p::tunnel::tunnels.Start();

	// Stop threads before destructor called to avoid crash on exit
	atexit(do_stop);
}


static
bool
do_init(void)
{
	do_setup();

	//
	// If FUZZING_BATCH env variable set, run batch mode.
	//
	// Pros:
	//   More data queued at once before time to process/empty all of it
	//   Better change of hitting thread bugs
	//
	// Cons:
	//   Input test data limited to 64k
	//   Input buffer under/over-reads may go un-noticed
	//
	if(getenv("FUZZING_BATCH") != nullptr)
		runner = run_batch;
	else
		runner = run_single;

	return true;
}


extern "C"
int
LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
	static bool inited = do_init();


	// Suppress compiler warning
	(void) inited;

	return runner(data, size) ? 0 : -1;
}
