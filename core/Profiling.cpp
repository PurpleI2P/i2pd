#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "util/base64.h"
#include "util/util.h"
#include "Profiling.h"

namespace i2p
{
namespace data
{
    RouterProfile::RouterProfile (const IdentHash& identHash):
        m_IdentHash (identHash), m_LastUpdateTime (boost::posix_time::second_clock::local_time()),
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
        
    void RouterProfile::Save ()
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
        auto path = i2p::util::filesystem::GetDefaultDataDir() / PEER_PROFILES_DIRECTORY;
        if (!boost::filesystem::exists (path))
        {
            // Create directory is necessary
            if (!boost::filesystem::create_directory (path))
            {   
                LogPrint (eLogError, "Failed to create directory ", path);
                return;
            }           
            const char * chars = i2p::util::GetBase64SubstitutionTable (); // 64 bytes
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
                        LogPrint (eLogWarning, "Missing section ", PEER_PROFILE_SECTION_PARTICIPATION);
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
                        LogPrint (eLogWarning, "Missing section ", PEER_PROFILE_SECTION_USAGE);
                    }   
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
        auto profile = std::make_shared<RouterProfile> (identHash);
        profile->Load (); // if possible
        return profile;
    }       

    void DeleteObsoleteProfiles ()
    {
        int num = 0;
        auto ts = boost::posix_time::second_clock::local_time();
        boost::filesystem::path p (i2p::util::filesystem::GetDataDir()/PEER_PROFILES_DIRECTORY);
        if (boost::filesystem::exists (p))
        {
            boost::filesystem::directory_iterator end;
            for (boost::filesystem::directory_iterator it (p); it != end; ++it)
            {
                if (boost::filesystem::is_directory (it->status()))
                {
                    for (boost::filesystem::directory_iterator it1 (it->path ()); it1 != end; ++it1)
                    {
                        auto lastModified = boost::posix_time::from_time_t (boost::filesystem::last_write_time (it1->path ()));
                        if ((ts - lastModified).hours () >= PEER_PROFILE_EXPIRATION_TIMEOUT)
                        {   
                            boost::filesystem::remove (it1->path ());
                            num++;
                        }   
                    }   
                }
            }   
        }
        LogPrint (eLogInfo, num, " obsolete profiles deleted");
    }   
}       
}   
