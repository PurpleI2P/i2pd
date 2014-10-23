#include <fstream>
#include <algorithm>
#include <cryptopp/dh.h>
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
		m_CurrentOutboundTunnel (nullptr), m_LeaseSet (nullptr), m_IsPublic (isPublic),
		m_DatagramDestination (nullptr)
	{		
		m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (sigType);
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (*this, 3); // 3-hops tunnel
		if (m_IsPublic)
			LogPrint ("Local address ", GetIdentHash ().ToBase32 (), ".b32.i2p created");
		m_StreamingDestination = new i2p::stream::StreamingDestination (*this); // TODO:
	}

	ClientDestination::ClientDestination (const std::string& fullPath, bool isPublic):
		m_IsRunning (false), m_Thread (nullptr), m_Service (nullptr), m_Work (nullptr),
		m_CurrentOutboundTunnel (nullptr), m_LeaseSet (nullptr), m_IsPublic (isPublic),
		m_DatagramDestination (nullptr)
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
		m_StreamingDestination = new i2p::stream::StreamingDestination (*this); // TODO:
	}

	ClientDestination::ClientDestination (const i2p::data::PrivateKeys& keys, bool isPublic):
		m_IsRunning (false), m_Thread (nullptr), m_Service (nullptr), m_Work (nullptr),	
		m_Keys (keys), m_CurrentOutboundTunnel (nullptr), m_LeaseSet (nullptr), m_IsPublic (isPublic),
		m_DatagramDestination (nullptr)
	{
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (*this, 3); // 3-hops tunnel 
		if (m_IsPublic)
			LogPrint ("Local address ", GetIdentHash ().ToBase32 (), ".b32.i2p created");
		m_StreamingDestination = new i2p::stream::StreamingDestination (*this); // TODO:
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
		delete m_StreamingDestination;
		delete m_DatagramDestination;
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
		m_StreamingDestination->Start ();	
	}
		
	void ClientDestination::Stop ()
	{	
		m_StreamingDestination->Stop ();	
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
		switch (buf[9])
		{
			case PROTOCOL_TYPE_STREAMING:
				// streaming protocol
				if (m_StreamingDestination)
					m_StreamingDestination->HandleDataMessagePayload (buf, length);
				else
					LogPrint ("Missing streaming destination");
			break;
			case PROTOCOL_TYPE_DATAGRAM:
				// datagram protocol
				if (m_DatagramDestination)
					m_DatagramDestination->HandleDataMessagePayload (buf, length);
				else
					LogPrint ("Missing streaming destination");
			break;
			default:
				LogPrint ("Data: unexpected protocol ", buf[9]);
		}
	}	

	i2p::stream::Stream * ClientDestination::CreateStream (const i2p::data::LeaseSet& remote, int port)
	{
		if (m_StreamingDestination)
			return m_StreamingDestination->CreateNewOutgoingStream (remote, port);
		return nullptr;	
	}		

	void ClientDestination::AcceptStreams (const std::function<void (i2p::stream::Stream *)>& acceptor)
	{
		if (m_StreamingDestination)
			m_StreamingDestination->SetAcceptor (acceptor);
	}

	void ClientDestination::StopAcceptingStreams ()
	{
		if (m_StreamingDestination)
			m_StreamingDestination->ResetAcceptor ();
	}

	bool ClientDestination::IsAcceptingStreams () const
	{
		if (m_StreamingDestination)
			return m_StreamingDestination->IsAcceptorSet ();
		return false;
	}	

	void ClientDestination::CreateDatagramDestination ()
	{
		if (!m_DatagramDestination)
			m_DatagramDestination = new i2p::datagram::DatagramDestination (*this);
	}
}
}
