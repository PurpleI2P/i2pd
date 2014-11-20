#ifndef RESEED_H
#define RESEED_H

#include <string>
#include <vector>

namespace i2p
{
namespace data
{

	class Reseeder
	{
		public:
			Reseeder();
			~Reseeder();
			bool reseedNow();
	};

	void ProcessSU3File (const char * filename);	
}
}

#endif
