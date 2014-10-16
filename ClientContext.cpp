#include "util.h"
#include "ClientContext.h"

namespace i2p
{
namespace client
{
	ClientContext context;	
	void ClientContext::Start ()
	{
		if (!m_SharedLocalDestination)
		{	
			m_SharedLocalDestination = new i2p::stream::StreamingDestination (false, i2p::data::SIGNING_KEY_TYPE_DSA_SHA1); // non-public, DSA
			m_Destinations[m_SharedLocalDestination->GetIdentity ().GetIdentHash ()] = m_SharedLocalDestination;
			m_SharedLocalDestination->Start ();
		}
	}
		
	void ClientContext::Stop ()
	{
		for (auto it: m_Destinations)
		{	
			it.second->Stop ();
			delete it.second;
		}		
		m_Destinations.clear ();
		m_SharedLocalDestination = 0; // deleted through m_Destination
	}	

	void ClientContext::LoadLocalDestinations ()
	{
		int numDestinations = 0;
		boost::filesystem::path p (i2p::util::filesystem::GetDataDir());
		boost::filesystem::directory_iterator end;
		for (boost::filesystem::directory_iterator it (p); it != end; ++it)
		{
			if (boost::filesystem::is_regular_file (*it) && it->path ().extension () == ".dat")
			{
				auto fullPath =
#if BOOST_VERSION > 10500
				it->path().string();
#else
				it->path();
#endif
				auto localDestination = new i2p::stream::StreamingDestination (fullPath, true);
				m_Destinations[localDestination->GetIdentHash ()] = localDestination;
				numDestinations++;
			}	
		}	
		if (numDestinations > 0)
			LogPrint (numDestinations, " local destinations loaded");
	}	
	
	i2p::stream::StreamingDestination * ClientContext::LoadLocalDestination (const std::string& filename, bool isPublic)
	{
		auto localDestination = new i2p::stream::StreamingDestination (i2p::util::filesystem::GetFullPath (filename), isPublic);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);	
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	i2p::stream::StreamingDestination * ClientContext::CreateNewLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType)
	{
		auto localDestination = new i2p::stream::StreamingDestination (isPublic, sigType);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	void ClientContext::DeleteLocalDestination (i2p::stream::StreamingDestination * destination)
	{
		if (!destination) return;
		auto it = m_Destinations.find (destination->GetIdentHash ());
		if (it != m_Destinations.end ())
		{
			auto d = it->second;
			{
				std::unique_lock<std::mutex> l(m_DestinationsMutex);
				m_Destinations.erase (it);
			}	
			d->Stop ();
			delete d;
		}
	}

	i2p::stream::StreamingDestination * ClientContext::CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic)
	{
		auto it = m_Destinations.find (keys.GetPublic ().GetIdentHash ());
		if (it != m_Destinations.end ())
		{
			LogPrint ("Local destination ", keys.GetPublic ().GetIdentHash ().ToBase32 (), ".b32.i2p exists");
			if (!it->second->IsRunning ())
			{	
				it->second->Start ();
				return it->second;
			}	
			return nullptr;
		}	
		auto localDestination = new i2p::stream::StreamingDestination (keys, isPublic);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[keys.GetPublic ().GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}
	
	i2p::stream::StreamingDestination * ClientContext::FindLocalDestination (const i2p::data::IdentHash& destination) const
	{
		auto it = m_Destinations.find (destination);
		if (it != m_Destinations.end ())
			return it->second;
		return nullptr;
	}	

	i2p::stream::StreamingDestination * GetSharedLocalDestination ()
	{
		return context.GetSharedLocalDestination ();
	}	
	
	i2p::stream::StreamingDestination * CreateNewLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType)
	{
		return context.CreateNewLocalDestination (isPublic, sigType);
	}

	i2p::stream::StreamingDestination * CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic)
	{
		return context.CreateNewLocalDestination (keys, isPublic);
	}

	void DeleteLocalDestination (i2p::stream::StreamingDestination * destination)
	{
		context.DeleteLocalDestination (destination);
	}

	i2p::stream::StreamingDestination * FindLocalDestination (const i2p::data::IdentHash& destination)
	{
		return context.FindLocalDestination (destination);
	}

	i2p::stream::StreamingDestination * LoadLocalDestination (const std::string& filename, bool isPublic)
	{
		return context.LoadLocalDestination (filename, isPublic);
	}		
}		
}	
