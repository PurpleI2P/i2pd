/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <sys/stat.h>
#include <unordered_map>
#include <list>
#include <thread>
#include <iomanip>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "Base.h"
#include "FS.h"
#include "Log.h"
#include "Timestamp.h"
#include "NetDb.hpp"
#include "Profiling.h"

namespace i2p
{
namespace data
{
	static i2p::fs::HashedStorage g_ProfilesStorage("peerProfiles", "p", "profile-", "txt");
	static std::unordered_map<i2p::data::IdentHash, std::shared_ptr<RouterProfile> > g_Profiles;
	static std::mutex g_ProfilesMutex;

	RouterProfile::RouterProfile ():
		m_IsUpdated (false), m_LastDeclineTime (0), m_LastUnreachableTime (0),
		m_LastUpdateTime (i2p::util::GetSecondsSinceEpoch ()), 
		m_NumTunnelsAgreed (0), m_NumTunnelsDeclined (0), m_NumTunnelsNonReplied (0),
		m_NumTimesTaken (0), m_NumTimesRejected (0), m_HasConnected (false),
		m_IsDuplicated (false)
	{
	}

	void RouterProfile::UpdateTime ()
	{
		m_LastUpdateTime = i2p::util::GetSecondsSinceEpoch ();
		m_IsUpdated = true;
	}

	void RouterProfile::Save (const IdentHash& identHash)
	{
		// fill sections
		boost::property_tree::ptree participation;
		participation.put (PEER_PROFILE_PARTICIPATION_AGREED, m_NumTunnelsAgreed);
		participation.put (PEER_PROFILE_PARTICIPATION_DECLINED, m_NumTunnelsDeclined);
		participation.put (PEER_PROFILE_PARTICIPATION_NON_REPLIED, m_NumTunnelsNonReplied);
		boost::property_tree::ptree usage;
		usage.put (PEER_PROFILE_USAGE_TAKEN, m_NumTimesTaken);
		usage.put (PEER_PROFILE_USAGE_REJECTED, m_NumTimesRejected);
		usage.put (PEER_PROFILE_USAGE_CONNECTED, m_HasConnected);
		if (m_IsDuplicated)
			usage.put (PEER_PROFILE_USAGE_DUPLICATED, true);
		// fill property tree
		boost::property_tree::ptree pt;
		pt.put (PEER_PROFILE_LAST_UPDATE_TIMESTAMP, m_LastUpdateTime);
		if (m_LastUnreachableTime)
			pt.put (PEER_PROFILE_LAST_UNREACHABLE_TIME, m_LastUnreachableTime);
		pt.put_child (PEER_PROFILE_SECTION_PARTICIPATION, participation);
		pt.put_child (PEER_PROFILE_SECTION_USAGE, usage);

		// save to file
		std::string ident = identHash.ToBase64 ();
		std::string path = g_ProfilesStorage.Path(ident);

		try {
			boost::property_tree::write_ini (path, pt);
		} catch (std::exception& ex) {
			/* boost exception verbose enough */
			LogPrint (eLogError, "Profiling: ", ex.what ());
		}
	}

	void RouterProfile::Load (const IdentHash& identHash)
	{
		std::string ident = identHash.ToBase64 ();
		std::string path = g_ProfilesStorage.Path(ident);
		boost::property_tree::ptree pt;

		if (!i2p::fs::Exists(path))
		{
			LogPrint(eLogWarning, "Profiling: No profile yet for ", ident);
			return;
		}

		try
		{
			boost::property_tree::read_ini (path, pt);
		} catch (std::exception& ex)
		{
			/* boost exception verbose enough */
			LogPrint (eLogError, "Profiling: ", ex.what ());
			return;
		}

		try
		{
			auto ts = pt.get (PEER_PROFILE_LAST_UPDATE_TIMESTAMP, 0);
			if (ts)
				m_LastUpdateTime = ts;
			else	
			{	
				// try old lastupdatetime 
				auto ut = pt.get (PEER_PROFILE_LAST_UPDATE_TIME, "");
				if (ut.length () > 0)
				{	
					std::istringstream ss (ut); std::tm t;
					ss >> std::get_time(&t, "%Y-%b-%d %H:%M:%S");
					if (!ss.fail())
						m_LastUpdateTime = mktime (&t); // t is local time
				}	
			}	
			if (i2p::util::GetSecondsSinceEpoch () - m_LastUpdateTime < PEER_PROFILE_EXPIRATION_TIMEOUT)
			{
				m_LastUnreachableTime = pt.get (PEER_PROFILE_LAST_UNREACHABLE_TIME, 0);
				try
				{
					// read participations
					auto participations = pt.get_child (PEER_PROFILE_SECTION_PARTICIPATION);
					m_NumTunnelsAgreed = participations.get (PEER_PROFILE_PARTICIPATION_AGREED, 0);
					m_NumTunnelsDeclined = participations.get (PEER_PROFILE_PARTICIPATION_DECLINED, 0);
					m_NumTunnelsNonReplied = participations.get (PEER_PROFILE_PARTICIPATION_NON_REPLIED, 0);
				}
				catch (boost::property_tree::ptree_bad_path& ex)
				{
					LogPrint (eLogWarning, "Profiling: Missing section ", PEER_PROFILE_SECTION_PARTICIPATION, " in profile for ", ident);
				}
				try
				{
					// read usage
					auto usage = pt.get_child (PEER_PROFILE_SECTION_USAGE);
					m_NumTimesTaken = usage.get (PEER_PROFILE_USAGE_TAKEN, 0);
					m_NumTimesRejected = usage.get (PEER_PROFILE_USAGE_REJECTED, 0);
					m_HasConnected = usage.get (PEER_PROFILE_USAGE_CONNECTED, false);
					m_IsDuplicated = usage.get (PEER_PROFILE_USAGE_DUPLICATED, false);
				}
				catch (boost::property_tree::ptree_bad_path& ex)
				{
					LogPrint (eLogWarning, "Profiling: Missing section ", PEER_PROFILE_SECTION_USAGE, " in profile for ", ident);
				}
			}
			else
				*this = RouterProfile ();
		}
		catch (std::exception& ex)
		{
			LogPrint (eLogError, "Profiling: Can't read profile ", ident, " :", ex.what ());
		}
	}

	void RouterProfile::TunnelBuildResponse (uint8_t ret)
	{
		UpdateTime ();
		if (ret > 0)
		{
			m_NumTunnelsDeclined++;
			m_LastDeclineTime = i2p::util::GetSecondsSinceEpoch ();
		}
		else
		{
		    m_NumTunnelsAgreed++;
			m_LastDeclineTime = 0;
		}
	}

	void RouterProfile::TunnelNonReplied ()
	{
	    m_NumTunnelsNonReplied++;
		UpdateTime ();
		if (m_NumTunnelsNonReplied > 2*m_NumTunnelsAgreed && m_NumTunnelsNonReplied > 3)
		{
			m_LastDeclineTime = i2p::util::GetSecondsSinceEpoch ();
		}
	}

	void RouterProfile::Unreachable (bool unreachable)
	{
		m_LastUnreachableTime = unreachable ? i2p::util::GetSecondsSinceEpoch () : 0;
		UpdateTime ();
	}
		
	void RouterProfile::Connected ()
	{
		m_HasConnected = true;
		UpdateTime ();
	}

	void RouterProfile::Duplicated ()
	{
		m_IsDuplicated = true;
	}	
		
	bool RouterProfile::IsLowPartcipationRate () const
	{
		return 4*m_NumTunnelsAgreed < m_NumTunnelsDeclined; // < 20% rate
	}

	bool RouterProfile::IsLowReplyRate () const
	{
		auto total = m_NumTunnelsAgreed + m_NumTunnelsDeclined;
		return m_NumTunnelsNonReplied > 10*(total + 1);
	}

	bool RouterProfile::IsDeclinedRecently ()
	{
		if (!m_LastDeclineTime) return false;
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		if (ts > m_LastDeclineTime + PEER_PROFILE_DECLINED_RECENTLY_INTERVAL ||
		    ts + PEER_PROFILE_DECLINED_RECENTLY_INTERVAL < m_LastDeclineTime)
			m_LastDeclineTime = 0;
		return (bool)m_LastDeclineTime;
	}

	bool RouterProfile::IsBad ()
	{
		if (IsDeclinedRecently () || IsUnreachable () || m_IsDuplicated) return true;
		auto isBad = IsAlwaysDeclining () || IsLowPartcipationRate () /*|| IsLowReplyRate ()*/;
		if (isBad && m_NumTimesRejected > 10*(m_NumTimesTaken + 1))
		{
			// reset profile
			m_NumTunnelsAgreed = 0;
			m_NumTunnelsDeclined = 0;
			m_NumTunnelsNonReplied = 0;
			isBad = false;
		}
		if (isBad) m_NumTimesRejected++; else m_NumTimesTaken++;
		return isBad;
	}

	bool RouterProfile::IsUnreachable ()
	{
		if (!m_LastUnreachableTime) return false;
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		if (ts > m_LastUnreachableTime + PEER_PROFILE_UNREACHABLE_INTERVAL ||
		    ts + PEER_PROFILE_UNREACHABLE_INTERVAL < m_LastUnreachableTime)
			m_LastUnreachableTime = 0;
		return (bool)m_LastUnreachableTime;
	}

	bool RouterProfile::IsUseful() const 
	{
	    return IsReal () || m_NumTunnelsNonReplied >= PEER_PROFILE_USEFUL_THRESHOLD;
	}

	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash)
	{
		{
			std::unique_lock<std::mutex> l(g_ProfilesMutex);
			auto it = g_Profiles.find (identHash);
			if (it != g_Profiles.end ())
				return it->second;
		}
		auto profile = netdb.NewRouterProfile ();
		profile->Load (identHash); // if possible
		std::unique_lock<std::mutex> l(g_ProfilesMutex);
		g_Profiles.emplace (identHash, profile);
		return profile;
	}

	bool IsRouterBanned (const IdentHash& identHash)
	{
		std::unique_lock<std::mutex> l(g_ProfilesMutex);
		auto it = g_Profiles.find (identHash);
		if (it != g_Profiles.end ())
			return it->second->IsUnreachable ();
		return false;
	}	
		
	void InitProfilesStorage ()
	{
		g_ProfilesStorage.SetPlace(i2p::fs::GetDataDir());
		g_ProfilesStorage.Init(i2p::data::GetBase64SubstitutionTable(), 64);
	}

	static void SaveProfilesToDisk (std::list<std::pair<i2p::data::IdentHash, std::shared_ptr<RouterProfile> > >&& profiles)
	{
		for (auto& it: profiles)
			if (it.second) it.second->Save (it.first);
	}	
		
	std::future<void> PersistProfiles ()
	{
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		std::list<std::pair<i2p::data::IdentHash, std::shared_ptr<RouterProfile> > > tmp;
		{
			std::unique_lock<std::mutex> l(g_ProfilesMutex);
			for (auto it = g_Profiles.begin (); it != g_Profiles.end ();)
			{
				if (ts - it->second->GetLastUpdateTime () > PEER_PROFILE_PERSIST_INTERVAL)
				{
					if (it->second->IsUpdated ())
						tmp.push_back (std::make_pair (it->first, it->second));
					it = g_Profiles.erase (it);
				}
				else
					it++;
			}
		}
		if (!tmp.empty ())
			return std::async (std::launch::async, SaveProfilesToDisk, std::move (tmp));
		return std::future<void>();
	}

	void SaveProfiles ()
	{
		std::unordered_map<i2p::data::IdentHash, std::shared_ptr<RouterProfile> > tmp;
		{
			std::unique_lock<std::mutex> l(g_ProfilesMutex);
			std::swap (tmp, g_Profiles);
		}
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		for (auto& it: tmp)
			if (it.second->IsUseful() && (it.second->IsUpdated () || ts - it.second->GetLastUpdateTime () < PEER_PROFILE_EXPIRATION_TIMEOUT))
				it.second->Save (it.first);
	}

	static void DeleteFilesFromDisk ()
	{
		std::vector<std::string> files;
		g_ProfilesStorage.Traverse(files);
		
		struct stat st;
		std::time_t now = std::time(nullptr);
		for (const auto& path: files) 
		{
			if (stat(path.c_str(), &st) != 0) 
			{	
				LogPrint(eLogWarning, "Profiling: Can't stat(): ", path);
				continue;
			}
			if (now - st.st_mtime >= PEER_PROFILE_EXPIRATION_TIMEOUT) 
			{
				LogPrint(eLogDebug, "Profiling: Removing expired peer profile: ", path);
				i2p::fs::Remove(path);
			}
		}
	}	
		
	std::future<void> DeleteObsoleteProfiles ()
	{
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			std::unique_lock<std::mutex> l(g_ProfilesMutex);
			for (auto it = g_Profiles.begin (); it != g_Profiles.end ();)
			{
				if (ts - it->second->GetLastUpdateTime () >= PEER_PROFILE_EXPIRATION_TIMEOUT)
					it = g_Profiles.erase (it);
				else
					it++;
			}
		}

		return std::async (std::launch::async, DeleteFilesFromDisk);
	}
}
}
