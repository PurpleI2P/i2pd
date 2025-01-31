/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef PROFILING_H__
#define PROFILING_H__

#include <memory>
#include <future>
#include <functional>
#include <boost/asio.hpp>
#include "Identity.h"

namespace i2p
{
namespace data
{
	// sections
	const char PEER_PROFILE_SECTION_PARTICIPATION[] = "participation";
	const char PEER_PROFILE_SECTION_USAGE[] = "usage";
	// params
	const char PEER_PROFILE_LAST_UPDATE_TIME[] = "lastupdatetime"; // deprecated
	const char PEER_PROFILE_LAST_UPDATE_TIMESTAMP[] = "lastupdatetimestamp";
	const char PEER_PROFILE_LAST_UNREACHABLE_TIME[] = "lastunreachabletime";
	const char PEER_PROFILE_PARTICIPATION_AGREED[] = "agreed";
	const char PEER_PROFILE_PARTICIPATION_DECLINED[] = "declined";
	const char PEER_PROFILE_PARTICIPATION_NON_REPLIED[] = "nonreplied";
	const char PEER_PROFILE_USAGE_TAKEN[] = "taken";
	const char PEER_PROFILE_USAGE_REJECTED[] = "rejected";
	const char PEER_PROFILE_USAGE_CONNECTED[] = "connected";
	const char PEER_PROFILE_USAGE_DUPLICATED[] = "duplicated";
	
	const int PEER_PROFILE_EXPIRATION_TIMEOUT = 36*60*60; // in seconds (1.5 days)
	const int PEER_PROFILE_AUTOCLEAN_TIMEOUT = 1500; // in seconds (25 minutes)
	const int PEER_PROFILE_AUTOCLEAN_VARIANCE = 900; // in seconds (15 minutes)
	const int PEER_PROFILE_OBSOLETE_PROFILES_CLEAN_TIMEOUT = 5400; // in seconds (1.5 hours)
	const int PEER_PROFILE_OBSOLETE_PROFILES_CLEAN_VARIANCE = 2400; // in seconds (40 minutes)
	const int PEER_PROFILE_DECLINED_RECENTLY_INTERVAL = 330; // in seconds (5.5 minutes)
	const int PEER_PROFILE_MAX_DECLINED_INTERVAL = 4400; // in second (1.5 hours)
	const int PEER_PROFILE_PERSIST_INTERVAL = 3300; // in seconds (55 minutes)
	const int PEER_PROFILE_UNREACHABLE_INTERVAL = 480; // in seconds (8 minutes)
	const int PEER_PROFILE_USEFUL_THRESHOLD = 3;
	const int PEER_PROFILE_ALWAYS_DECLINING_NUM = 5; // num declines in row to consider always declined
	const int PEER_PROFILE_APPLY_POSTPONED_TIMEOUT = 2100; // in milliseconds	
	const int PEER_PROFILE_APPLY_POSTPONED_TIMEOUT_VARIANCE = 500; // in milliseconds	
	
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
			void Duplicated ();

			uint64_t GetLastUpdateTime () const { return m_LastUpdateTime; };
			bool IsUpdated () const { return m_IsUpdated; };
			void SetUpdated (bool updated) { m_IsUpdated = updated; }
			uint64_t GetLastAccessTime () const { return m_LastAccessTime; };
			void SetLastAccessTime (uint64_t ts) { m_LastAccessTime = ts; };
			uint64_t GetLastPersistTime () const { return m_LastPersistTime; };
			void SetLastPersistTime (uint64_t ts) { m_LastPersistTime = ts; };
			
			bool IsUseful() const;
			bool IsDuplicated () const { return m_IsDuplicated; };

			const boost::asio::ip::udp::endpoint& GetLastEndpoint () const { return m_LastEndpoint; }
			void SetLastEndpoint (const boost::asio::ip::udp::endpoint& ep) { m_LastEndpoint = ep; }
			bool HasLastEndpoint (bool v4) const { return !m_LastEndpoint.address ().is_unspecified () && m_LastEndpoint.port () && 
				((v4 && m_LastEndpoint.address ().is_v4 ()) || (!v4 && m_LastEndpoint.address ().is_v6 ())); }
			
		private:

			void UpdateTime ();

			bool IsAlwaysDeclining () const { return !m_NumTunnelsAgreed && m_NumTunnelsDeclined >= 5; };
			bool IsLowPartcipationRate () const;
			bool IsLowReplyRate () const;
			bool IsDeclinedRecently (uint64_t ts);

		private:

			bool m_IsUpdated;
			uint64_t m_LastDeclineTime, m_LastUnreachableTime, m_LastUpdateTime, 
				m_LastAccessTime, m_LastPersistTime; // in seconds
			// participation
			uint32_t m_NumTunnelsAgreed;
			uint32_t m_NumTunnelsDeclined;
			uint32_t m_NumTunnelsNonReplied;
			// usage
			uint32_t m_NumTimesTaken;
			uint32_t m_NumTimesRejected;
			bool m_HasConnected; // successful trusted(incoming or NTCP2) connection 
			bool m_IsDuplicated;
			// connectivity
			boost::asio::ip::udp::endpoint m_LastEndpoint; // SSU2 for non-published addresses
	};

	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash);
	bool IsRouterBanned (const IdentHash& identHash); // check only existing profiles
	bool IsRouterDuplicated (const IdentHash& identHash); // check only existing profiles
	void InitProfilesStorage ();
	std::future<void> DeleteObsoleteProfiles ();
	void SaveProfiles ();
	std::future<void> PersistProfiles ();
	bool UpdateRouterProfile (const IdentHash& identHash, std::function<void (std::shared_ptr<RouterProfile>)> update); // return true if updated immediately, and false if postponed
	std::future<void> FlushPostponedRouterProfileUpdates ();
}
}

#endif
