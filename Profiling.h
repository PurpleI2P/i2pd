#ifndef PROFILING_H__
#define PROFILING_H__

#include <memory>
#include "Identity.h"

namespace i2p
{
namespace data
{
	class RouterProfile
	{
		public:

			RouterProfile (const IdentHash& identHash);
			
		private:	

			IdentHash m_IdentHash;
			// participation
			uint32_t m_NumTunnelsAgreed;
			uint32_t m_NumTunnelsDeclined;			
	};	

	std::shared_ptr<RouterProfile> GetProfile (const IdentHash& identHash); 
}		
}	

#endif
