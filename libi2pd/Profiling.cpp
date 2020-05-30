/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <sys/stat.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "Base.h"
#include "FS.h"
#include "Log.h"
#include "Profiling.h"

namespace i2p
{
namespace data
{
	i2p::fs::HashedStorage m_ProfilesStorage("peerProfiles", "p", "profile-", "txt");

	RouterProfile::RouterProfile ():
		m_LastUpdateTime (boost::posix_time::second_clock::local_time()),
		m_NumTunnelsAgreed (0), m_NumTunnelsDeclined (0), m_NumTunnelsNonReplied (0),
		m_NumTimesTaken (0), m_NumTimesRejected (0)
	{
	}

	boost::posix_time::ptime RouterProfile::GetTime () const
	{
		return boost::posix_time::second_clock::local_time();
	}

	void RouterProfile::UpdateTime ()
	{
		m_LastUpdateTime = GetTime ();
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
		// fill property tree
		boost::property_tree::ptree pt;
		pt.put (PEER_PROFILE_LAST_UPDATE_TIME, boost::posix_time::to_simple_string (m_LastUpdateTime));
		pt.put_child (PEER_PROFILE_SECTION_PARTICIPATION, participation);
		pt.put_child (PEER_PROFILE_SECTION_USAGE, usage);

		// save to file
		std::string ident = identHash.ToBase64 ();
		std::string path = m_ProfilesStorage.Path(ident);

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
		std::string path = m_ProfilesStorage.Path(ident);
		boost::property_tree::ptree pt;

		if (!i2p::fs::Exists(path))
		{
			LogPrint(eLogWarning, "Profiling: no profile yet for ", ident);
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
			auto t = pt.get (PEER_PROFILE_LAST_UPDATE_TIME, "");
			if (t.length () > 0)
				m_LastUpdateTime = boost::posix_time::time_from_string (t);
			if ((GetTime () - m_LastUpdateTime).hours () < PEER_PROFILE_EXPIRATION_TIMEOUT)
			{
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
				}
				catch (boost::property_tree::ptree_bad_path& ex)
				{
					LogPrint (eLogWarning, "Missing section ", PEER_PROFILE_SECTION_USAGE, " in profile for ", ident);
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
			m_NumTunnelsDeclined++;
		else
			m_NumTunnelsAgreed++;
	}

	void RouterProfile::TunnelNonReplied ()
	{
		m_NumTunnelsNonReplied++;
		UpdateTime ();
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

	bool RouterProfile::IsBad ()
	{
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

	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash)
	{
		auto profile = std::make_shared<RouterProfile> ();
		profile->Load (identHash); // if possible
		return profile;
	}

	void InitProfilesStorage ()
	{
		m_ProfilesStorage.SetPlace(i2p::fs::GetDataDir());
		m_ProfilesStorage.Init(i2p::data::GetBase64SubstitutionTable(), 64);
	}

	void DeleteObsoleteProfiles ()
	{
		struct stat st;
		std::time_t now = std::time(nullptr);

		std::vector<std::string> files;
		m_ProfilesStorage.Traverse(files);
		for (const auto& path: files) {
			if (stat(path.c_str(), &st) != 0) {
				LogPrint(eLogWarning, "Profiling: Can't stat(): ", path);
				continue;
			}
			if (((now - st.st_mtime) / 3600) >= PEER_PROFILE_EXPIRATION_TIMEOUT) {
				LogPrint(eLogDebug, "Profiling: removing expired peer profile: ", path);
				i2p::fs::Remove(path);
			}
		}
	}
}
}
