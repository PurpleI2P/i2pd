#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "base64.h"
#include "util.h"
#include "Profiling.h"

namespace i2p
{
namespace data
{
	RouterProfile::RouterProfile (const IdentHash& identHash):
		m_IdentHash (identHash), m_LastUpdateTime (boost::posix_time::second_clock::local_time()),
		m_NumTunnelsAgreed (0), m_NumTunnelsDeclined (0),
		m_NumTunnelsNonReplied (0)
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
		
	void RouterProfile::Save ()
	{
		// fill sections
		boost::property_tree::ptree participation;
		participation.put (PEER_PROFILE_PARTICIPATION_AGREED, m_NumTunnelsAgreed);
		participation.put (PEER_PROFILE_PARTICIPATION_DECLINED, m_NumTunnelsDeclined);
		participation.put (PEER_PROFILE_PARTICIPATION_NON_REPLIED, m_NumTunnelsNonReplied);
		// fill property tree
		boost::property_tree::ptree pt;
		pt.put (PEER_PROFILE_LAST_UPDATE_TIME, boost::posix_time::to_simple_string (m_LastUpdateTime));
		pt.put_child (PEER_PROFILE_SECTION_PARTICIPATION, participation);
		
		// save to file
		auto path = i2p::util::filesystem::GetDefaultDataDir() / PEER_PROFILES_DIRECTORY;
		if (!boost::filesystem::exists (path))
		{
			// Create directory is necessary
			if (!boost::filesystem::create_directory (path))
			{	
				LogPrint (eLogError, "Failed to create directory ", path);
				return;
			}			
			const char * chars = GetBase64SubstitutionTable (); // 64 bytes
			for (int i = 0; i < 64; i++)
			{
				auto path1 = path / (std::string ("p") + chars[i]);
				if (!boost::filesystem::create_directory (path1)) 
				{
					LogPrint (eLogError, "Failed to create directory ", path1);
					return;
				}			
			}				
		}
		std::string base64 = m_IdentHash.ToBase64 ();
		path = path / (std::string ("p") + base64[0]);
		auto filename = path / (std::string (PEER_PROFILE_PREFIX) + base64 + ".txt");
		try
		{
			boost::property_tree::write_ini (filename.string (), pt);
		}
		catch (std::exception& ex)
		{
			LogPrint (eLogError, "Can't write ", filename, ": ", ex.what ());
		}
	}	

	void RouterProfile::Load ()
	{
		std::string base64 = m_IdentHash.ToBase64 ();
		auto path = i2p::util::filesystem::GetDefaultDataDir() / PEER_PROFILES_DIRECTORY;
		path /= std::string ("p") + base64[0];
		auto filename = path / (std::string (PEER_PROFILE_PREFIX) + base64 + ".txt");
		if (boost::filesystem::exists (filename))
		{	
			boost::property_tree::ptree pt;
			try
			{
				boost::property_tree::read_ini (filename.string (), pt);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Can't read ", filename, ": ", ex.what ());
				return;
			}
			try
			{	
				auto t = pt.get (PEER_PROFILE_LAST_UPDATE_TIME, "");
				if (t.length () > 0)
					m_LastUpdateTime = boost::posix_time::time_from_string (t);
				if ((GetTime () - m_LastUpdateTime).hours () < 72) // profile becomes obsolete after 3 days of inactivity
				{	
					// read participations
					auto participations = pt.get_child (PEER_PROFILE_SECTION_PARTICIPATION);
					m_NumTunnelsAgreed = participations.get (PEER_PROFILE_PARTICIPATION_AGREED, 0);
					m_NumTunnelsDeclined = participations.get (PEER_PROFILE_PARTICIPATION_DECLINED, 0);
					m_NumTunnelsNonReplied = participations.get (PEER_PROFILE_PARTICIPATION_NON_REPLIED, 0);
				}	
				else
					*this = RouterProfile (m_IdentHash);
			}	
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Can't read profile ", base64, " :", ex.what ());
			}	
		}	
	}	
		
	void RouterProfile::TunnelBuildResponse (uint8_t ret)
	{
		if (ret > 0)
			m_NumTunnelsDeclined++;
		else
			m_NumTunnelsAgreed++;
		UpdateTime ();
	}	

	void RouterProfile::TunnelNonReplied ()
	{
		m_NumTunnelsNonReplied++;
		UpdateTime ();
	}	

	bool RouterProfile::IsLowPartcipationRate () const
	{
		if ((GetTime () - m_LastUpdateTime).total_seconds () < 900) // if less than 15 minutes
			return m_NumTunnelsAgreed < m_NumTunnelsDeclined; // 50% rate
		else
			return 4*m_NumTunnelsAgreed < m_NumTunnelsDeclined; // 20% rate
	}	
		
	bool RouterProfile::IsBad () const 
	{ 
		return IsAlwaysDeclining () || IsNonResponding () || IsLowPartcipationRate (); 
	}
		
	std::shared_ptr<RouterProfile> GetRouterProfile (const IdentHash& identHash)
	{
		auto profile = std::make_shared<RouterProfile> (identHash);
		profile->Load (); // if possible
		return profile;
	}		
}		
}	