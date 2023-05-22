/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <sys/stat.h>
#include <unordered_map>
#include <list>
#include <thread>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "Base.h"
#include "FS.h"
#include "Log.h"
#include "Timestamp.h"
#include "Profiling.h"

namespace i2p
{
namespace data
{
	static std::unordered_map<i2p::data::IdentHash, std::shared_ptr<RouterProfile> > g_Profiles;
	static std::mutex g_ProfilesMutex;

	static uint64_t GetTime ()
	{
		return i2p::util::GetSecondsSinceEpoch ();
	}

	RouterProfile::RouterProfile ():
		m_LastUpdateTime (0), m_LastDeclineTime (0), m_LastUnreachableTime (0),
		m_NumTunnelsAgreed (0), m_NumTunnelsDeclined (0), m_NumTunnelsNonReplied (0),
		m_NumTimesTaken (0), m_NumTimesRejected (0), m_HasConnected (false)
	{
	}

	std::string RouterProfile::Dump (const std::string& peerid)
	{
		boost::property_tree::ptree pt;
		std::stringstream ss;

		pt.put(PEER_PROFILE_PEER_ID, peerid);
		/* "times" hash */
		pt.put(PEER_PROFILE_LAST_UPDATE_TIME,      m_LastUpdateTime);
		pt.put(PEER_PROFILE_LAST_DECLINE_TIME,     m_LastDeclineTime);
		pt.put(PEER_PROFILE_LAST_UNREACHABLE_TIME, m_LastUnreachableTime);
		/* "tunnels" hash */
		pt.put(PEER_PROFILE_PARTICIPATION_AGREED,      m_NumTunnelsAgreed);
		pt.put(PEER_PROFILE_PARTICIPATION_DECLINED,    m_NumTunnelsDeclined);
		pt.put(PEER_PROFILE_PARTICIPATION_NON_REPLIED, m_NumTunnelsNonReplied);
		/* "usage" hash */
		pt.put(PEER_PROFILE_USAGE_TAKEN,     m_NumTimesTaken);
		pt.put(PEER_PROFILE_USAGE_REJECTED,  m_NumTimesRejected);
		pt.put(PEER_PROFILE_USAGE_CONNECTED, m_HasConnected);

		try {
			/* convert ptree to single line json string */
			boost::property_tree::write_json (ss, pt, false);
		} catch (std::exception& ex) {
			/* boost exception verbose enough */
			LogPrint (eLogError, "Profiling: can't serialize data to json -- ", ex.what ());
		}
		return ss.str();
	}

	std::string RouterProfile::Load (const std::string& jsondata)
	{
		boost::property_tree::ptree pt;
		std::stringstream ss(jsondata);
		std::string peerid = "";

		try {
			boost::property_tree::read_json (ss, pt);
		} catch (std::exception& ex) {
			/* boost exception verbose enough */
			LogPrint (eLogError, "Profiling: can't parse json data -- ", ex.what ());
			return std::string("");
		}

		try {
			peerid = pt.get<std::string>(PEER_PROFILE_PEER_ID);
		} catch (std::exception& ex) {
			LogPrint (eLogError, "Profiling: Can't read profile data: missing peerid");
			return std::string("");
		}
		try {
			/* "lasttime" hash */
			m_LastUpdateTime       = pt.get<int>(PEER_PROFILE_LAST_UPDATE_TIME, 0);
			m_LastDeclineTime      = pt.get<int>(PEER_PROFILE_LAST_DECLINE_TIME, 0);
			m_LastUnreachableTime  = pt.get<int>(PEER_PROFILE_LAST_UNREACHABLE_TIME, 0);
			/* "tunnels" hash */
			m_NumTunnelsAgreed     = pt.get<int>(PEER_PROFILE_PARTICIPATION_AGREED, 0);
			m_NumTunnelsDeclined   = pt.get<int>(PEER_PROFILE_PARTICIPATION_DECLINED, 0);
			m_NumTunnelsNonReplied = pt.get<int>(PEER_PROFILE_PARTICIPATION_NON_REPLIED, 0);
			/* "usage" hash */
			m_NumTimesTaken     = pt.get<int>(PEER_PROFILE_USAGE_TAKEN, 0);
			m_NumTimesRejected  = pt.get<int>(PEER_PROFILE_USAGE_REJECTED, 0);
			m_HasConnected      = pt.get<bool>(PEER_PROFILE_USAGE_CONNECTED, false);
		} catch (boost::property_tree::ptree_bad_path& ex) {
			LogPrint (eLogError, "Profiling: Can't read profile data: ", ex.what());
		}
		return peerid;
	}

	void RouterProfile::TunnelBuildResponse (uint8_t ret)
	{
		if (ret > 0) {
			m_NumTunnelsDeclined++;
			m_LastDeclineTime = GetTime ();
		} else {
			m_NumTunnelsAgreed++;
			m_LastDeclineTime = 0;
		}
		m_LastUpdateTime = GetTime ();
	}

	void RouterProfile::TunnelNonReplied ()
	{
		m_NumTunnelsNonReplied++;
		if (m_NumTunnelsNonReplied > 2*m_NumTunnelsAgreed && m_NumTunnelsNonReplied > 3)
			m_LastDeclineTime = GetTime ();
		m_LastUpdateTime = GetTime ();
	}

	void RouterProfile::Unreachable ()
	{
		m_LastUnreachableTime = GetTime ();
		m_LastUpdateTime = GetTime ();
	}

	void RouterProfile::Connected ()
	{
		m_HasConnected = true;
		m_LastUpdateTime = GetTime ();
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
		if (IsDeclinedRecently () || IsUnreachable ()) return true;
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

	bool RouterProfile::IsUseful() const {
	    return
	        m_NumTunnelsAgreed >= PEER_PROFILE_USEFUL_THRESHOLD ||
	        m_NumTunnelsDeclined >= PEER_PROFILE_USEFUL_THRESHOLD ||
	        m_NumTunnelsNonReplied >= PEER_PROFILE_USEFUL_THRESHOLD ||
	        m_HasConnected;
	}


	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash)
	{
		{
			std::unique_lock<std::mutex> l(g_ProfilesMutex);
			auto it = g_Profiles.find (identHash);
			if (it != g_Profiles.end ())
				return it->second;
		}
		LogPrint(eLogDebug, "Profiling: creating new profile for ", identHash.ToBase64());
		auto profile = std::make_shared<RouterProfile> ();
		std::unique_lock<std::mutex> l(g_ProfilesMutex);
		g_Profiles.emplace (identHash, profile);
		return profile;
	}

	void LoadProfilesDB () {
		unsigned int loaded = 0, linenum = 0;
		static std::unordered_map<i2p::data::IdentHash, std::shared_ptr<RouterProfile> > new_db;
		IdentHash identHash;
		std::string oldDBDir = i2p::fs::DataDirPath("peerProfiles");
		auto DBPath = i2p::fs::DataDirPath(PEER_PROFILES_DB_FILENAME);
		if (i2p::fs::Exists(oldDBDir)) {
			std::string oldDBBak = oldDBDir + ".bak";
			LogPrint(eLogInfo, "Profiling: old peerProfiles/ directory still exists, you may safely remove it");
			std::rename(oldDBDir.c_str(), oldDBBak.c_str());
		}
		if (!i2p::fs::Exists(DBPath))
			return; /* no database yet */

		std::ifstream in (DBPath);
		if (!in.is_open()) {
			LogPrint (eLogError, "Profiling: can't open profiles database ", DBPath);
			return;
		}

		std::string line;
		while (!(in.eof() || in.fail())) {
			std::getline(in, line); linenum++;
			if (line.empty()) continue;
			if (line[0] != '{') {
				LogPrint(eLogError, "Profiling: ignore profile data at line ", linenum);
				continue;
			}
			auto profile = std::make_shared<RouterProfile> ();
			std::string peerid = profile->Load(line);
			if (peerid.empty())
				continue; /* load failed, errors logged */
			identHash.FromBase64(peerid);
			new_db.emplace(identHash, profile);
			loaded++;
		}
		LogPrint (eLogInfo, "Profiling: loaded ", loaded, " profiles");

		{ /* replace exiting database with just loaded */
			std::unique_lock<std::mutex> l(g_ProfilesMutex);
			g_Profiles.clear ();
			g_Profiles = new_db;
		}
		return;
	}

	void PruneExpiredProfiles () {
		unsigned int pruned = 0;
		auto ts = GetTime ();
		std::unique_lock<std::mutex> l(g_ProfilesMutex);
		for (auto it = g_Profiles.begin (); it != g_Profiles.end (); ) {
			if ((ts - it->second->GetLastUpdateTime ()) >= PEER_PROFILE_EXPIRATION_TIMEOUT * 3600) {
				it = g_Profiles.erase (it);
				pruned++;
			} else {
				it++;
			}
		}
		LogPrint(eLogInfo, "Profiling: pruned ", pruned, " expired peer profiles, ", g_Profiles.size(), " remains");
	}

	void SaveProfilesDB () {
		unsigned int saved = 0;
		auto DBPath = i2p::fs::DataDirPath(PEER_PROFILES_DB_FILENAME);
		auto DBPathNew = DBPath + ".new";
	  std::ofstream out (DBPathNew);
		std::unique_lock<std::mutex> l(g_ProfilesMutex);
		if (!out.is_open()) {
			LogPrint(eLogError, "Profiling: can't open database file ", DBPathNew);
			return;
		}
		auto ts = GetTime ();
		/* save "old enough" profiles */
		for (auto& it : g_Profiles) {
			if (it.second->IsUseful() && (ts - it.second->GetLastUpdateTime ()) < PEER_PROFILE_PERSIST_INTERVAL)
				continue; /* too new */
			out << it.second->Dump(it.first.ToBase64());
			saved++;
		}
		out.flush();
		out.close();
		LogPrint(eLogDebug, "Profiling: db path is", DBPath);
		std::rename(DBPathNew.c_str(), DBPath.c_str());
		LogPrint(eLogInfo, "Profiling: saved ", saved, " peer profiles");
	}

	void ClearProfilesDB () {
		g_Profiles.clear();
	}
}
}
