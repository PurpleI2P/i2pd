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
				"http://netdb.i2p2.no/",
				"http://reseed.i2p-projekt.de/",
				"http://cowpuncher.drollette.com/netdb/",
				"http://i2p.mooo.com/netDb/",
				"http://reseed.info/",
				"http://reseed.pkol.de/",
				"http://uk.reseed.i2p2.no/",
				"http://i2p-netdb.innovatio.no/",
				"http://ieb9oopo.mooo.com"
			};
	};

}
}

#endif