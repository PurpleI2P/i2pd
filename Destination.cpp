#include <fstream>
#include <algorithm>
#include <cryptopp/dh.h>
#include <cryptopp/gzip.h>
#include "Log.h"
#include "util.h"
#include "NetDb.h"
#include "Destination.h"

namespace i2p
{
namespace client
{
	ClientDestination::ClientDestination (bool isPublic, i2p::data::SigningKeyType sigType): 
		m_IsRunning (false), m_Thread (nullptr), m_Service (nullptr), m_Work (nullptr), 
		m_CurrentOutboundTunnel (nullptr), m_LeaseSet (nullptr), m_IsPublic (isPublic)
	{		
		m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (sigType);
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (*this, 3); // 3-hops tunnel
		if (m_IsPublic)
			LogPrint ("Local address ", GetIdentHash ().ToBase32 (), ".b32.i2p created");
	}

	ClientDestination::ClientDestination (const std::string& fullPath, bool isPublic):
		m_IsRunning (false), m_Thread (nullptr), m_Service (nullptr), m_Work (nullptr),
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
			m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (i2p::data::SIGNING_KEY_TYPE_DSA_SHA1); 
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

	ClientDestination::ClientDestination (const i2p::data::PrivateKeys& keys, bool isPublic):
		m_IsRunning (false), m_Thread (nullptr), m_Service (nullptr), m_Work (nullptr),	
		m_Keys (keys), m_CurrentOutboundTunnel (nullptr), m_LeaseSet (nullptr), m_IsPublic (isPublic)
	{
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (*this, 3); // 3-hops tunnel 
		if (m_IsPublic)
			LogPrint ("Local address ", GetIdentHash ().ToBase32 (), ".b32.i2p created");
	}

	ClientDestination::~ClientDestination ()
	{
		Stop ();
		for (auto it: m_RemoteLeaseSets)
			delete it.second;
		if (m_Pool)
			i2p::tunnel::tunnels.DeleteTunnelPool (m_Pool);		
		delete m_LeaseSet;
		delete m_Work;
		delete m_Service;
	}	

	void ClientDestination::Run ()
	{
		if (m_Service)
			m_Service->run ();
	}	

	void ClientDestination::Start ()
	{	
		m_Service = new boost::asio::io_service;
		m_Work = new boost::asio::io_service::work (*m_Service);
		m_Pool->SetActive (true);
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&ClientDestination::Run, this));
	}
		
	void ClientDestination::Stop ()
	{	
		if (m_Pool)
			i2p::tunnel::tunnels.StopTunnelPool (m_Pool);
		m_IsRunning = false;
		if (m_Service)
			m_Service->stop ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
		}	
		delete m_Work; m_Work = nullptr;
		delete m_Service; m_Service = nullptr;
	}	

	const i2p::data::LeaseSet * ClientDestination::FindLeaseSet (const i2p::data::IdentHash& ident)
	{
		auto it = m_RemoteLeaseSets.find (ident);
		if (it != m_RemoteLeaseSets.end ())
		{	
			if (it->second->HasNonExpiredLeases ())
				return it->second;
			else
			{
				LogPrint ("All leases of remote LeaseSet expired. Request it");
				i2p::data::netdb.RequestDestination (ident, true, m_Pool);
			}	
		}	
		else
		{	
			auto ls = i2p::data::netdb.FindLeaseSet (ident);
			if (ls)
			{
				ls = new i2p::data::LeaseSet (*ls);
				m_RemoteLeaseSets[ident] = ls;			
				return ls;
			}	
		}
		return nullptr;
	}	

	const i2p::data::LeaseSet * ClientDestination::GetLeaseSet ()
	{
		if (!m_Pool) return nullptr;
		if (!m_LeaseSet)
			UpdateLeaseSet ();
		return m_LeaseSet;
	}	

	void ClientDestination::UpdateLeaseSet ()
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

	void ClientDestination::SendTunnelDataMsgs (const std::vector<i2p::tunnel::TunnelMessageBlock>& msgs)
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

	void ClientDestination::ProcessGarlicMessage (I2NPMessage * msg)
	{
		m_Service->post (boost::bind (&ClientDestination::HandleGarlicMessage, this, msg)); 
	}

	void ClientDestination::ProcessDeliveryStatusMessage (I2NPMessage * msg)
	{
		m_Service->post (boost::bind (&ClientDestination::HandleDeliveryStatusMessage, this, msg)); 
	}

	void ClientDestination::HandleI2NPMessage (const uint8_t * buf, size_t len, i2p::tunnel::InboundTunnel * from)
	{
		I2NPHeader * header = (I2NPHeader *)buf;
		switch (header->typeID)
		{	
			case eI2NPData:
				HandleDataMessage (buf + sizeof (I2NPHeader), be16toh (header->size));
			break;
			case eI2NPDatabaseStore:
				HandleDatabaseStoreMessage (buf + sizeof (I2NPHeader), be16toh (header->size));
				i2p::HandleI2NPMessage (CreateI2NPMessage (buf, GetI2NPMessageLength (buf), from)); // TODO: remove
			break;	
			default:
				i2p::HandleI2NPMessage (CreateI2NPMessage (buf, GetI2NPMessageLength (buf), from));
		}		
	}	

	void ClientDestination::HandleDatabaseStoreMessage (const uint8_t * buf, size_t len)
	{
		I2NPDatabaseStoreMsg * msg = (I2NPDatabaseStoreMsg *)buf;
		size_t offset = sizeof (I2NPDatabaseStoreMsg);
		if (msg->replyToken) // TODO:
			offset += 36;
		if (msg->type == 1) // LeaseSet
		{
			LogPrint ("Remote LeaseSet");
			auto it = m_RemoteLeaseSets.find (msg->key);
			if (it != m_RemoteLeaseSets.end ())
			{
				it->second->Update (buf + offset, len - offset); 
				LogPrint ("Remote LeaseSet updated");
			}
			else
			{	
				LogPrint ("New remote LeaseSet added");
				m_RemoteLeaseSets[msg->key] = new i2p::data::LeaseSet (buf + offset, len - offset);
			}	
		}	
		else
			LogPrint ("Unexpected client's DatabaseStore type ", msg->type, ". Dropped");
	}	

	void ClientDestination::SetLeaseSetUpdated ()
	{
		i2p::garlic::GarlicDestination::SetLeaseSetUpdated ();	
		UpdateLeaseSet ();
		if (m_IsPublic)
			i2p::data::netdb.PublishLeaseSet (m_LeaseSet, m_Pool);
	}

	void ClientDestination::HandleDataMessage (const uint8_t * buf, size_t len)
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
			i2p::stream::Packet * uncompressed = new i2p::stream::Packet;
			uncompressed->offset = 0;
			uncompressed->len = decompressor.MaxRetrievable ();
			if (uncompressed->len <= i2p::stream::MAX_PACKET_SIZE)
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
	
	I2NPMessage * ClientDestination::CreateDataMessage (const uint8_t * payload, size_t len)
	{
		I2NPMessage * msg = NewI2NPShortMessage ();
		CryptoPP::Gzip compressor;
		if (len <= i2p::stream::COMPRESSION_THRESHOLD_SIZE)
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
}

namespace stream
{

	void StreamingDestination::Start ()
	{	
		ClientDestination::Start ();
	}
		
	void StreamingDestination::Stop ()
	{	
		ResetAcceptor ();
		{
			std::unique_lock<std::mutex> l(m_StreamsMutex);
			for (auto it: m_Streams)
				delete it.second;	
			m_Streams.clear ();
		}	
		ClientDestination::Stop ();		
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
		Stream * s = new Stream (*GetService (), *this, remote);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}	

	Stream * StreamingDestination::CreateNewIncomingStream ()
	{
		Stream * s = new Stream (*GetService (), *this);
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
				if (GetService ())
					GetService ()->post ([stream](void) { delete stream; }); 
				else
					delete stream;
			}	
		}	
	}	
}		
}
