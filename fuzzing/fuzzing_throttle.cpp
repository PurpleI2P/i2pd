
#include <thread>

#include "fuzzing.h"


static unsigned int counter = 0;


void
fuzzing_tick(void)
{
	counter++;
}


void
fuzzing_throttle(void)
{
	unsigned int delay;


	// Give queues time to drain (avoid OOM or crash)
	// - Too high a delay slows down fuzzing
	// - Too low a delay causes intermittent crash on exit
	delay = 50 + (counter / 50);
	counter = 0;

	if(delay > 5000)
		delay = 5000;

	std::this_thread::sleep_for (std::chrono::milliseconds(delay));
}
