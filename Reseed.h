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

}
}

#endif