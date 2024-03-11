/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
	const char PEER_PROFILE_LAST_UNREACHABLE_TIME[] = "lastunreachabletime";
	const char PEER_PROFILE_PARTICIPATION_AGREED[] = "agreed";
	const char PEER_PROFILE_PARTICIPATION_DECLINED[] = "declined";
	const char PEER_PROFILE_PARTICIPATION_NON_REPLIED[] = "nonreplied";
	const char PEER_PROFILE_USAGE_TAKEN[] = "taken";
	const char PEER_PROFILE_USAGE_REJECTED[] = "rejected";
	const char PEER_PROFILE_USAGE_CONNECTED[] = "connected";
	
	const int PEER_PROFILE_EXPIRATION_TIMEOUT = 36; // in hours (1.5 days)
	const int PEER_PROFILE_AUTOCLEAN_TIMEOUT = 3 * 3600; // in seconds (3 hours)
	const int PEER_PROFILE_AUTOCLEAN_VARIANCE = 3600; // in seconds (1 hour)
	const int PEER_PROFILE_DECLINED_RECENTLY_INTERVAL = 150; // in seconds (2.5 minutes)
	const int PEER_PROFILE_PERSIST_INTERVAL = 3300; // in seconds (55 minutes)
	const int PEER_PROFILE_UNREACHABLE_INTERVAL = 480; // in seconds (8 minutes)
	const int PEER_PROFILE_USEFUL_THRESHOLD = 3;

	class RouterProfile
	{
		public:

			RouterProfile ();

			void Save (const IdentHash& identHash);
			void Load (const IdentHash& identHash);

			bool IsBad ();
			bool IsUnreachable ();
			bool IsReal () const { return m_HasConnected || m_NumTunnelsAgreed > 0 || m_NumTunnelsDeclined > 0; } 

			void TunnelBuildResponse (uint8_t ret);
			void TunnelNonReplied ();

			void Unreachable (bool unreachable);
			void Connected ();

			boost::posix_time::ptime GetLastUpdateTime () const { return m_LastUpdateTime; };
			bool IsUpdated () const { return m_IsUpdated; };
			
			bool IsUseful() const;
			
		private:

			void UpdateTime ();

			bool IsAlwaysDeclining () const { return !m_NumTunnelsAgreed && m_NumTunnelsDeclined >= 5; };
			bool IsLowPartcipationRate () const;
			bool IsLowReplyRate () const;
			bool IsDeclinedRecently ();

		private:

			boost::posix_time::ptime m_LastUpdateTime; // TODO: use std::chrono
			bool m_IsUpdated;
			uint64_t m_LastDeclineTime, m_LastUnreachableTime; // in seconds
			// participation
			uint32_t m_NumTunnelsAgreed;
			uint32_t m_NumTunnelsDeclined;
			uint32_t m_NumTunnelsNonReplied;
			// usage
			uint32_t m_NumTimesTaken;
			uint32_t m_NumTimesRejected;
			bool m_HasConnected; // successful trusted(incoming or NTCP2) connection 
	};

	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash);
	bool IsRouterBanned (const IdentHash& identHash); // check only existing profiles
	void InitProfilesStorage ();
	void DeleteObsoleteProfiles ();
	void SaveProfiles ();
	void PersistProfiles ();
}
}

#endif
