/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef PROFILING_H__
#define PROFILING_H__

#include <memory>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "Identity.h"

namespace i2p
{
namespace data
{
	// sections
	const char PEER_PROFILE_SECTION_PARTICIPATION[] = "participation";
	const char PEER_PROFILE_SECTION_USAGE[] = "usage";
	// params
	const char PEER_PROFILE_LAST_UPDATE_TIME[] = "lastupdatetime";
	const char PEER_PROFILE_PARTICIPATION_AGREED[] = "agreed";
	const char PEER_PROFILE_PARTICIPATION_DECLINED[] = "declined";
	const char PEER_PROFILE_PARTICIPATION_NON_REPLIED[] = "nonreplied";
	const char PEER_PROFILE_USAGE_TAKEN[] = "taken";
	const char PEER_PROFILE_USAGE_REJECTED[] = "rejected";

	const int PEER_PROFILE_EXPIRATION_TIMEOUT = 72; // in hours (3 days)

	class RouterProfile
	{
		public:

			RouterProfile ();
			RouterProfile& operator= (const RouterProfile& ) = default;

			void Save (const IdentHash& identHash);
			void Load (const IdentHash& identHash);

			bool IsBad ();

			void TunnelBuildResponse (uint8_t ret);
			void TunnelNonReplied ();

		private:

			boost::posix_time::ptime GetTime () const;
			void UpdateTime ();

			bool IsAlwaysDeclining () const { return !m_NumTunnelsAgreed && m_NumTunnelsDeclined >= 5; };
			bool IsLowPartcipationRate () const;
			bool IsLowReplyRate () const;

		private:

			boost::posix_time::ptime m_LastUpdateTime;
			// participation
			uint32_t m_NumTunnelsAgreed;
			uint32_t m_NumTunnelsDeclined;
			uint32_t m_NumTunnelsNonReplied;
			// usage
			uint32_t m_NumTimesTaken;
			uint32_t m_NumTimesRejected;
	};

	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash);
	void InitProfilesStorage ();
	void DeleteObsoleteProfiles ();
}
}

#endif
