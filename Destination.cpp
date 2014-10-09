#include <fstream>
#include <algorithm>
#include <cryptopp/dh.h>
#include <cryptopp/gzip.h>
#include "Log.h"
#include "util.h"
#include "Destination.h"

namespace i2p
{
namespace stream
{
	StreamingDestination::StreamingDestination (bool isPublic): 
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service), 
		m_CurrentOutboundTunnel (nullptr), m_LeaseSet (nullptr), m_IsPublic (isPublic)
	{		
		m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (/*i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256*/); // uncomment for ECDSA
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (*this, 3); // 3-hops tunnel
		if (m_IsPublic)
			LogPrint ("Local address ", GetIdentHash ().ToBase32 (), ".b32.i2p created");
	}

	StreamingDestination::StreamingDestination (const std::string& fullPath, bool isPublic):
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service),
		m_CurrentOutboundTunnel (nullptr), m_LeaseSet (nullptr), m_IsPublic (isPublic) 
	{
		std::ifstream s(fullPath.c_str (), std::ifstream::binary);
		if (s.is_open ())	
		{	
			s.seekg (0, std::ios::end);
			size_t len = s.tellg();
			s.seekg (0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			s.read ((char *)buf, len);
			m_Keys.FromBuffer (buf, len);
			delete[] buf;
			LogPrint ("Local address ", GetIdentHash ().ToBase32 (), ".b32.i2p loaded");
		}	
		else
		{
			LogPrint ("Can't open file ", fullPath, " Creating new one");
			m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (/*i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256*/); 
			std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
			size_t len = m_Keys.GetFullLen ();
			uint8_t * buf = new uint8_t[len];
			len = m_Keys.ToBuffer (buf, len);
			f.write ((char *)buf, len);
			delete[] buf;
			
			LogPrint ("New private keys file ", fullPath, " for ", m_Keys.GetPublic ().GetIdentHash ().ToBase32 (), ".b32.i2p created");
		}	

		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (*this, 3); // 3-hops tunnel 
	}

	StreamingDestination::StreamingDestination (const i2p::data::PrivateKeys& keys, bool isPublic):
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service),	
		m_Keys (keys), m_CurrentOutboundTunnel (nullptr), m_LeaseSet (nullptr), m_IsPublic (isPublic)
	{
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (*this, 3); // 3-hops tunnel 
		if (m_IsPublic)
			LogPrint ("Local address ", GetIdentHash ().ToBase32 (), ".b32.i2p created");
	}

	StreamingDestination::~StreamingDestination ()
	{
		{
			std::unique_lock<std::mutex> l(m_StreamsMutex);
			for (auto it: m_Streams)
				delete it.second;
			m_Streams.clear ();
		}	
		Stop ();
		if (m_Pool)
			i2p::tunnel::tunnels.DeleteTunnelPool (m_Pool);		
		delete m_LeaseSet;
	}	

	void StreamingDestination::Run ()
	{
		m_Service.run ();
	}	

	void StreamingDestination::Start ()
	{	
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&StreamingDestination::Run, this));
	}
		
	void StreamingDestination::Stop ()
	{	
		m_IsRunning = false;
		m_Service.stop ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
		}	
	}	

	void StreamingDestination::SendTunnelDataMsgs (const std::vector<i2p::tunnel::TunnelMessageBlock>& msgs)
	{
		m_CurrentOutboundTunnel = m_Pool->GetNextOutboundTunnel (m_CurrentOutboundTunnel);
		if (m_CurrentOutboundTunnel)
			m_CurrentOutboundTunnel->SendTunnelDataMsg (msgs);
		else
		{
			LogPrint ("No outbound tunnels in the pool");
			for (auto it: msgs)
				DeleteI2NPMessage (it.data);
		}
	}

	void StreamingDestination::HandleNextPacket (Packet * packet)
	{
		uint32_t sendStreamID = packet->GetSendStreamID ();
		if (sendStreamID)
		{	
			auto it = m_Streams.find (sendStreamID);
			if (it != m_Streams.end ())
				it->second->HandleNextPacket (packet);
			else
			{	
				LogPrint ("Unknown stream ", sendStreamID);
				delete packet;
			}
		}	
		else // new incoming stream
		{
			auto incomingStream = CreateNewIncomingStream ();
			incomingStream->HandleNextPacket (packet);
			if (m_Acceptor != nullptr)
				m_Acceptor (incomingStream);
			else
			{
				LogPrint ("Acceptor for incoming stream is not set");
				DeleteStream (incomingStream);
			}
		}	
	}	

	Stream * StreamingDestination::CreateNewOutgoingStream (const i2p::data::LeaseSet& remote)
	{
		Stream * s = new Stream (m_Service, *this, remote);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}	

	Stream * StreamingDestination::CreateNewIncomingStream ()
	{
		Stream * s = new Stream (m_Service, *this);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}

	void StreamingDestination::DeleteStream (Stream * stream)
	{
		if (stream)
		{	
			std::unique_lock<std::mutex> l(m_StreamsMutex);
			auto it = m_Streams.find (stream->GetRecvStreamID ());
			if (it != m_Streams.end ())
			{	
				m_Streams.erase (it);
				delete stream;
			}	
		}	
	}	

	const i2p::data::LeaseSet * StreamingDestination::GetLeaseSet ()
	{
		if (!m_Pool) return nullptr;
		if (!m_LeaseSet)
			UpdateLeaseSet ();
		return m_LeaseSet;
	}	

	void StreamingDestination::UpdateLeaseSet ()
	{
		auto newLeaseSet = new i2p::data::LeaseSet (*m_Pool);
		if (!m_LeaseSet)
			m_LeaseSet = newLeaseSet;
		else
		{	
			// TODO: implement it better
			*m_LeaseSet = *newLeaseSet;
			delete newLeaseSet;
		}	
	}	
	
	void StreamingDestination::HandleDataMessage (const uint8_t * buf, size_t len)
	{
		uint32_t length = be32toh (*(uint32_t *)buf);
		buf += 4;
		// we assume I2CP payload
		if (buf[9] == 6) // streaming protocol
		{	
			// unzip it
			CryptoPP::Gunzip decompressor;
			decompressor.Put (buf, length);
			decompressor.MessageEnd();
			Packet * uncompressed = new Packet;
			uncompressed->offset = 0;
			uncompressed->len = decompressor.MaxRetrievable ();
			if (uncompressed->len <= MAX_PACKET_SIZE)
			{
				decompressor.Get (uncompressed->buf, uncompressed->len);
				HandleNextPacket (uncompressed); 
			}
			else
			{
				LogPrint ("Received packet size ", uncompressed->len,  " exceeds max packet size. Skipped");
				decompressor.Skip ();
				delete uncompressed;
			}	
		}	
		else
			LogPrint ("Data: unexpected protocol ", buf[9]);
	}	
	
	I2NPMessage * StreamingDestination::CreateDataMessage (const uint8_t * payload, size_t len)
	{
		I2NPMessage * msg = NewI2NPShortMessage ();
		CryptoPP::Gzip compressor;
		if (len <= COMPRESSION_THRESHOLD_SIZE)
			compressor.SetDeflateLevel (CryptoPP::Gzip::MIN_DEFLATE_LEVEL);
		else
			compressor.SetDeflateLevel (CryptoPP::Gzip::DEFAULT_DEFLATE_LEVEL);
		compressor.Put (payload, len);
		compressor.MessageEnd();
		int size = compressor.MaxRetrievable ();
		uint8_t * buf = msg->GetPayload ();
		*(uint32_t *)buf = htobe32 (size); // length
		buf += 4;
		compressor.Get (buf, size);
		memset (buf + 4, 0, 4); // source and destination ports. TODO: fill with proper values later
		buf[9] = 6; // streaming protocol
		msg->len += size + 4; 
		FillI2NPMessageHeader (msg, eI2NPData);
		
		return msg;
	}		

	void StreamingDestination::SetLeaseSetUpdated ()
	{
		i2p::garlic::GarlicDestination::SetLeaseSetUpdated ();	
		UpdateLeaseSet ();
		if (m_IsPublic)
			i2p::data::netdb.PublishLeaseSet (m_LeaseSet, m_Pool);
	}	

	void StreamingDestination::ProcessGarlicMessage (I2NPMessage * msg)
	{
		m_Service.post (boost::bind (&StreamingDestination::HandleGarlicMessage, this, msg)); 
	}

	void StreamingDestination::ProcessDeliveryStatusMessage (I2NPMessage * msg)
	{
		m_Service.post (boost::bind (&StreamingDestination::HandleDeliveryStatusMessage, this, msg)); 
	}

	StreamingDestinations destinations;	
	void StreamingDestinations::Start ()
	{
		if (!m_SharedLocalDestination)
		{	
			m_SharedLocalDestination = new StreamingDestination (false); // non-public
			m_Destinations[m_SharedLocalDestination->GetIdentity ().GetIdentHash ()] = m_SharedLocalDestination;
			m_SharedLocalDestination->Start ();
		}
	}
		
	void StreamingDestinations::Stop ()
	{
		for (auto it: m_Destinations)
		{	
			it.second->Stop ();
			delete it.second;
		}		
		m_Destinations.clear ();
		m_SharedLocalDestination = 0; // deleted through m_Destination
	}	

	void StreamingDestinations::LoadLocalDestinations ()
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
				auto localDestination = new StreamingDestination (fullPath, true);
				m_Destinations[localDestination->GetIdentHash ()] = localDestination;
				numDestinations++;
			}	
		}	
		if (numDestinations > 0)
			LogPrint (numDestinations, " local destinations loaded");
	}	
	
	StreamingDestination * StreamingDestinations::LoadLocalDestination (const std::string& filename, bool isPublic)
	{
		auto localDestination = new StreamingDestination (i2p::util::filesystem::GetFullPath (filename), isPublic);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);	
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	StreamingDestination * StreamingDestinations::CreateNewLocalDestination (bool isPublic)
	{
		auto localDestination = new StreamingDestination (isPublic);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	void StreamingDestinations::DeleteLocalDestination (StreamingDestination * destination)
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

	StreamingDestination * StreamingDestinations::CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic)
	{
		auto it = m_Destinations.find (keys.GetPublic ().GetIdentHash ());
		if (it != m_Destinations.end ())
		{
			LogPrint ("Local destination ", keys.GetPublic ().GetIdentHash ().ToBase32 (), ".b32.i2p exists");
			return nullptr;
		}	
		auto localDestination = new StreamingDestination (keys, isPublic);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[keys.GetPublic ().GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	Stream * StreamingDestinations::CreateClientStream (const i2p::data::LeaseSet& remote)
	{
		if (!m_SharedLocalDestination) return nullptr;
		return m_SharedLocalDestination->CreateNewOutgoingStream (remote);
	}

	void StreamingDestinations::DeleteStream (Stream * stream)
	{
		if (stream)
			stream->GetLocalDestination ().DeleteStream (stream);
	}	
	
	StreamingDestination * StreamingDestinations::FindLocalDestination (const i2p::data::IdentHash& destination) const
	{
		auto it = m_Destinations.find (destination);
		if (it != m_Destinations.end ())
			return it->second;
		return nullptr;
	}	

	Stream * CreateStream (const i2p::data::LeaseSet& remote)
	{
		return destinations.CreateClientStream (remote);
	}
		
	void DeleteStream (Stream * stream)
	{
		destinations.DeleteStream (stream);
	}	

	void StartStreaming ()
	{
		destinations.Start ();
	}
		
	void StopStreaming ()
	{
		destinations.Stop ();
	}	

	StreamingDestination * GetSharedLocalDestination ()
	{
		return destinations.GetSharedLocalDestination ();
	}	
	
	StreamingDestination * CreateNewLocalDestination (bool isPublic)
	{
		return destinations.CreateNewLocalDestination (isPublic);
	}

	StreamingDestination * CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic)
	{
		return destinations.CreateNewLocalDestination (keys, isPublic);
	}

	void DeleteLocalDestination (StreamingDestination * destination)
	{
		destinations.DeleteLocalDestination (destination);
	}

	StreamingDestination * FindLocalDestination (const i2p::data::IdentHash& destination)
	{
		return destinations.FindLocalDestination (destination);
	}

	StreamingDestination * LoadLocalDestination (const std::string& filename, bool isPublic)
	{
		return destinations.LoadLocalDestination (filename, isPublic);
	}		

	const StreamingDestinations& GetLocalDestinations ()
	{
		return destinations;
	}	
}		
}
