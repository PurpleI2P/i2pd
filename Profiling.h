#ifndef PROFILING_H__
#define PROFILING_H__

#include <memory>
#include "Identity.h"

namespace i2p
{
namespace data
{	
	const char PEER_PROFILES_DIRECTORY[] = "peerProfiles";
	const char PEER_PROFILE_PREFIX[] = "profile-";
	// sections
	const char PEER_PROFILE_SECTION_PARTICIPATION[] = "participation";
	// params	
	const char PEER_PROFILE_PARTICIPATION_AGREED[] = "agreed";
	const char PEER_PROFILE_PARTICIPATION_DECLINED[] = "declined";
	
	class RouterProfile
	{
		public:

			RouterProfile (const IdentHash& identHash);
			
			void Save ();
			void Load ();

			bool IsBad () const { return !m_NumTunnelsAgreed && m_NumTunnelsDeclined >= 5; };
			
			void TunnelBuildResponse (uint8_t ret);
			
		private:	

			IdentHash m_IdentHash;
			// participation
			uint32_t m_NumTunnelsAgreed;
			uint32_t m_NumTunnelsDeclined;			
	};	

	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash); 
}		
}	

#endif
