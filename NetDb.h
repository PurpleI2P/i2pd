#ifndef NETDB_H__
#define NETDB_H__

#include <inttypes.h>
#include <map>
#include <string>
#include "RouterInfo.h"
#include "LeaseSet.h"

namespace i2p
{
namespace data
{		
	class NetDb
	{
		public:

			NetDb ();
			~NetDb ();
			
			void AddRouterInfo (uint8_t * buf, int len);
			void AddLeaseSet (uint8_t * buf, int len);
			RouterInfo * FindRouter (const uint8_t * ident);
			
			void RequestDestination (const uint8_t * destination, const uint8_t * router);
			
			const RouterInfo * GetNextFloodfill () const;
			
		private:

			void Load (const char * directory);
				
		private:

			std::map<std::string, LeaseSet *> m_LeaseSets;
			std::map<std::string, RouterInfo *> m_RouterInfos;
	};

	extern NetDb netdb;
}
}

#endif
