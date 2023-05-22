/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef PROFILING_H__
#define PROFILING_H__

#include <memory>
#include "Identity.h"

namespace i2p
{
namespace data
{
	const char PEER_PROFILES_DB_FILENAME[] = "peerProfiles.dat";
	/** example json peer profile (pretty-printed):
		{
			"peerid": "<base64-ident>",
			"lasttime": { "update": 123456789, "decline": 123456789, "unreachable": 123456789 },
			"tunnels": { "agreed": 17. "declined": 4, "noreply: 2 },
			"usage": { "taken": 10, "rejected": 3 }
		} */
	// params
	const char PEER_PROFILE_PEER_ID[] = "peerid";
	const char PEER_PROFILE_LAST_UPDATE_TIME[]      = "lasttime.update";
	const char PEER_PROFILE_LAST_DECLINE_TIME[]     = "lasttime.decline";
	const char PEER_PROFILE_LAST_UNREACHABLE_TIME[] = "lasttime.unreachable";
	const char PEER_PROFILE_PARTICIPATION_AGREED[]      = "tunnels.agreed";
	const char PEER_PROFILE_PARTICIPATION_DECLINED[]    = "tunnels.declined";
	const char PEER_PROFILE_PARTICIPATION_NON_REPLIED[] = "tunnels.noreply";
	const char PEER_PROFILE_USAGE_TAKEN[]    = "usage.taken";
	const char PEER_PROFILE_USAGE_REJECTED[] = "usage.rejected";
	const char PEER_PROFILE_USAGE_CONNECTED[] = "usage.connected";

	const int PEER_PROFILE_EXPIRATION_TIMEOUT = 36; // in hours (1.5 days)
	const int PEER_PROFILE_AUTOCLEAN_TIMEOUT = 6 * 3600; // in seconds (6 hours)
	const int PEER_PROFILE_AUTOCLEAN_VARIANCE = 3600; // in seconds (1 hour)
	const int PEER_PROFILE_DECLINED_RECENTLY_INTERVAL = 150; // in seconds (2.5 minutes)
	const int PEER_PROFILE_PERSIST_INTERVAL = 3300; // in seconds (55 minutes)
	const int PEER_PROFILE_UNREACHABLE_INTERVAL = 2*3600; // on seconds (2 hours)
	const int PEER_PROFILE_USEFUL_THRESHOLD = 3;

	class RouterProfile
	{
		public:

			RouterProfile ();
			RouterProfile& operator= (const RouterProfile& ) = default;

			std::string Dump (const std::string& peerid);
			std::string Load (const std::string& jsondata);

			bool IsBad ();
			bool IsUnreachable ();
			bool IsUseful() const;
			bool IsReal () const { return m_HasConnected || m_NumTunnelsAgreed > 0 || m_NumTunnelsDeclined > 0; } 

			void TunnelBuildResponse (uint8_t ret);
			void TunnelNonReplied ();

			void Unreachable ();
			void Connected ();

			uint64_t GetLastUpdateTime () const { return m_LastUpdateTime; };
			
		private:

			bool IsAlwaysDeclining () const { return !m_NumTunnelsAgreed && m_NumTunnelsDeclined >= 5; };
			bool IsLowPartcipationRate () const;
			bool IsLowReplyRate () const;
			bool IsDeclinedRecently ();

		private:

			// lasttime
			uint64_t m_LastUpdateTime;
			uint64_t m_LastDeclineTime;
			uint64_t m_LastUnreachableTime;
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

	/** database file operations */
	void LoadProfilesDB (); /*< read saved peer profiles from file to memory */
	void SaveProfilesDB (); /*< serialize and write to file known peer profiles */

	/** memory database operations */
	void PruneExpiredProfiles (); /*< discard peer profiles inactive for long time */
	void ClearProfilesDB ();      /*< discard ALL known peer profiles */
}
}

#endif
