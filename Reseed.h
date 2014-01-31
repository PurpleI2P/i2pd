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
		private:
			std::vector<std::string> httpReseedHostList = {
				"http://193.150.121.66/netDb/",
				"http://netdb.i2p2.no/"
			};
	};

}
}

#endif