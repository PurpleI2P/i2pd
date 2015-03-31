#ifndef PROFILING_H__
#define PROFILING_H__

#include <memory>
#include <boost/date_time/posix_time/posix_time.hpp>
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
	const char PEER_PROFILE_LAST_UPDATE_TIME[] = "lastupdatetime";
	const char PEER_PROFILE_PARTICIPATION_AGREED[] = "agreed";
	const char PEER_PROFILE_PARTICIPATION_DECLINED[] = "declined";
	const char PEER_PROFILE_PARTICIPATION_NON_REPLIED[] = "nonreplied";	
	
	class RouterProfile
	{
		public:

			RouterProfile (const IdentHash& identHash);
			RouterProfile& operator= (const RouterProfile& ) = default;
			
			void Save ();
			void Load ();

			bool IsBad () const;
			
			void TunnelBuildResponse (uint8_t ret);
			void TunnelNonReplied ();

		private:

			boost::posix_time::ptime GetTime () const;
			void UpdateTime ();

			bool IsAlwaysDeclining () const { return !m_NumTunnelsAgreed && m_NumTunnelsDeclined >= 5; };
			bool IsNonResponding () const { return m_NumTunnelsNonReplied > 20 && !(m_NumTunnelsAgreed + m_NumTunnelsDeclined); };
			bool IsLowPartcipationRate () const;
			
		private:	

			IdentHash m_IdentHash;
			boost::posix_time::ptime m_LastUpdateTime;
			// participation
			uint32_t m_NumTunnelsAgreed;
			uint32_t m_NumTunnelsDeclined;	
			uint32_t m_NumTunnelsNonReplied;
	};	

	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash); 
}		
}	

#endif
