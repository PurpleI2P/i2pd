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
	ClientDestination::ClientDestination (const i2p::data::PrivateKeys& keys, bool isPublic):
		m_IsRunning (false), m_Thread (nullptr), m_Service (nullptr), m_Work (nullptr),	
		m_Keys (keys), m_LeaseSet (nullptr), m_IsPublic (isPublic), m_PublishReplyToken (0),
		m_DatagramDestination (nullptr), m_PublishConfirmationTimer (nullptr)
	{
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (*this, 3, 3); // 3-hops tunnel 
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
		delete m_PublishConfirmationTimer;
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
		m_PublishConfirmationTimer = new boost::asio::deadline_timer (*m_Service);
		m_Work = new boost::asio::io_service::work (*m_Service);
		m_Pool->SetActive (true);
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&ClientDestination::Run, this));
		m_StreamingDestination->Start ();	
	}
		
	void ClientDestination::Stop ()
	{	
		m_StreamingDestination->Stop ();	
		if (m_DatagramDestination)
		{
			auto d = m_DatagramDestination;
			m_DatagramDestination = nullptr;
			delete d;
		}	
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
		delete m_PublishConfirmationTimer; m_PublishConfirmationTimer = nullptr;
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

	void ClientDestination::ProcessGarlicMessage (I2NPMessage * msg)
	{
		if (m_Service)
			m_Service->post (std::bind (&ClientDestination::HandleGarlicMessage, this, msg)); 
	}

	void ClientDestination::ProcessDeliveryStatusMessage (I2NPMessage * msg)
	{
		if (m_Service)
			m_Service->post (std::bind (&ClientDestination::HandleDeliveryStatusMessage, this, msg)); 
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
			LogPrint (eLogDebug, "Remote LeaseSet");
			auto it = m_RemoteLeaseSets.find (msg->key);
			if (it != m_RemoteLeaseSets.end ())
			{
				it->second->Update (buf + offset, len - offset); 
				LogPrint (eLogDebug, "Remote LeaseSet updated");
			}
			else
			{	
				LogPrint (eLogDebug, "New remote LeaseSet added");
				m_RemoteLeaseSets[msg->key] = new i2p::data::LeaseSet (buf + offset, len - offset);
			}	
		}	
		else
			LogPrint (eLogError, "Unexpected client's DatabaseStore type ", msg->type, ". Dropped");
	}	

	void ClientDestination::HandleDeliveryStatusMessage (I2NPMessage * msg)
	{
		I2NPDeliveryStatusMsg * deliveryStatus = (I2NPDeliveryStatusMsg *)msg->GetPayload ();
		uint32_t msgID = be32toh (deliveryStatus->msgID);
		if (msgID == m_PublishReplyToken)
		{
			LogPrint (eLogDebug, "Publishing confirmed");
			m_PublishReplyToken = 0;
			i2p::DeleteI2NPMessage (msg);
		}
		else
			i2p::garlic::GarlicDestination::HandleDeliveryStatusMessage (msg);
	}	

	void ClientDestination::SetLeaseSetUpdated ()
	{
		i2p::garlic::GarlicDestination::SetLeaseSetUpdated ();	
		UpdateLeaseSet ();
		if (m_IsPublic)
			Publish ();
	}

	void ClientDestination::Publish ()
	{	
		if (!m_LeaseSet || !m_Pool) 
		{
			LogPrint (eLogError, "Can't publish non-existing LeaseSet");
			return;
		}
		if (m_PublishReplyToken)
		{
			LogPrint (eLogInfo, "Publishing is pending");
			return;
		}
		auto outbound = m_Pool->GetNextOutboundTunnel ();
		if (!outbound)
		{
			LogPrint ("Can't publish LeaseSet. No outbound tunnels");
			return;
		}
		std::set<i2p::data::IdentHash> excluded; 
		auto floodfill = i2p::data::netdb.GetClosestFloodfill (m_LeaseSet->GetIdentHash (), excluded);	
		if (!floodfill)
		{
			LogPrint ("Can't publish LeaseSet. No floodfills found");
			return;
		}	
		LogPrint (eLogDebug, "Publish LeaseSet of ", GetIdentHash ().ToBase32 ());
		m_PublishReplyToken = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
		auto msg = WrapMessage (*floodfill, i2p::CreateDatabaseStoreMsg (m_LeaseSet, m_PublishReplyToken));	
		if (m_PublishConfirmationTimer)
		{
			m_PublishConfirmationTimer->expires_from_now (boost::posix_time::seconds(PUBLISH_CONFIRMATION_TIMEOUT));
			m_PublishConfirmationTimer->async_wait (std::bind (&ClientDestination::HandlePublishConfirmationTimer,
				this, std::placeholders::_1));
		}
		else
		{
			LogPrint (eLogWarning, "Destination's thread is not running");
			m_PublishReplyToken = 0;
		}		
		outbound->SendTunnelDataMsg (floodfill->GetIdentHash (), 0, msg);	
	}

	void ClientDestination::HandlePublishConfirmationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{	
			if (m_PublishReplyToken)
			{
				LogPrint (eLogWarning, "Publish confirmation was not received in ", PUBLISH_CONFIRMATION_TIMEOUT,  "seconds. Try again");
				m_PublishReplyToken = 0;
				Publish ();
			}
		}
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

	std::shared_ptr<i2p::stream::Stream> ClientDestination::CreateStream (const i2p::data::LeaseSet& remote, int port)
	{
		if (m_StreamingDestination)
			return m_StreamingDestination->CreateNewOutgoingStream (remote, port);
		return nullptr;	
	}		

	void ClientDestination::AcceptStreams (const i2p::stream::StreamingDestination::Acceptor& acceptor)
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

	i2p::datagram::DatagramDestination * ClientDestination::CreateDatagramDestination ()
	{
		if (!m_DatagramDestination)
			m_DatagramDestination = new i2p::datagram::DatagramDestination (*this);
		return m_DatagramDestination;	
	}
}
}
