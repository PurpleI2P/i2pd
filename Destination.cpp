#include <algorithm>
#include <cassert>
#include <boost/lexical_cast.hpp>
#include <openssl/rand.h>
#include "Log.h"
#include "util.h"
#include "Crypto.h"
#include "Timestamp.h"
#include "NetDb.h"
#include "Destination.h"

namespace i2p
{
namespace client
{
	ClientDestination::ClientDestination (const i2p::data::PrivateKeys& keys, bool isPublic, 
			const std::map<std::string, std::string> * params):
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service),	
		m_Keys (keys), m_IsPublic (isPublic), m_PublishReplyToken (0),
		m_DatagramDestination (nullptr), m_PublishConfirmationTimer (m_Service), m_CleanupTimer (m_Service)
	{
		if (m_IsPublic)	
			PersistTemporaryKeys ();
		else
			i2p::crypto::GenerateElGamalKeyPair(m_EncryptionPrivateKey, m_EncryptionPublicKey);
		int inboundTunnelLen = DEFAULT_INBOUND_TUNNEL_LENGTH;
		int outboundTunnelLen = DEFAULT_OUTBOUND_TUNNEL_LENGTH;
		int inboundTunnelsQuantity = DEFAULT_INBOUND_TUNNELS_QUANTITY;
		int outboundTunnelsQuantity = DEFAULT_OUTBOUND_TUNNELS_QUANTITY;
		int numTags = DEFAULT_TAGS_TO_SEND;
		std::shared_ptr<std::vector<i2p::data::IdentHash> > explicitPeers;
		if (params)
		{
			auto it = params->find (I2CP_PARAM_INBOUND_TUNNEL_LENGTH);
			if (it != params->end ())
			{	
				int len = boost::lexical_cast<int>(it->second);
				if (len > 0)
				{
					inboundTunnelLen = len;
					LogPrint (eLogInfo, "Destination: Inbound tunnel length set to ", len);
				}
			}	
			it = params->find (I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH);
			if (it != params->end ())
			{
				int len = boost::lexical_cast<int>(it->second);
				if (len > 0)
				{
					outboundTunnelLen = len;
					LogPrint (eLogInfo, "Destination: Outbound tunnel length set to ", len);
				}
			}	
			it = params->find (I2CP_PARAM_INBOUND_TUNNELS_QUANTITY);
			if (it != params->end ())
			{
				int quantity = boost::lexical_cast<int>(it->second);
				if (quantity > 0)
				{
					inboundTunnelsQuantity = quantity;
					LogPrint (eLogInfo, "Destination: Inbound tunnels quantity set to ", quantity);
				}	
			}
			it = params->find (I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY);
			if (it != params->end ())
			{
				int quantity = boost::lexical_cast<int>(it->second);
				if (quantity > 0)
				{
					outboundTunnelsQuantity = quantity;
					LogPrint (eLogInfo, "Destination: Outbound tunnels quantity set to ", quantity);
				}	
			}
			it = params->find (I2CP_PARAM_TAGS_TO_SEND);
			if (it != params->end ())
			{
				int tagsToSend = boost::lexical_cast<int>(it->second);
				if (tagsToSend > 0)
				{
					numTags = tagsToSend;
					LogPrint (eLogInfo, "Destination: Tags to send set to  ", tagsToSend);
				}	
			}	
			it = params->find (I2CP_PARAM_EXPLICIT_PEERS);
			if (it != params->end ())
			{
				explicitPeers = std::make_shared<std::vector<i2p::data::IdentHash> >();
				std::stringstream ss(it->second);
				std::string b64;
				while (std::getline (ss, b64, ','))
				{
					i2p::data::IdentHash ident;
					ident.FromBase64 (b64);
					explicitPeers->push_back (ident);
				}
				LogPrint (eLogInfo, "Destination: Explicit peers set to ", it->second);
			}
		}	
		SetNumTags (numTags);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (inboundTunnelLen, outboundTunnelLen, inboundTunnelsQuantity, outboundTunnelsQuantity);  
		if (explicitPeers)
			m_Pool->SetExplicitPeers (explicitPeers);
		if (m_IsPublic)
			LogPrint (eLogInfo, "Destination: Local address ", GetIdentHash().ToBase32 (), " created");
	}

	ClientDestination::~ClientDestination ()
	{
		if (m_IsRunning)	
			Stop ();
		for (auto it: m_LeaseSetRequests)
			if (it.second->requestComplete) it.second->requestComplete (nullptr);
		m_LeaseSetRequests.clear ();
		if (m_Pool)
			i2p::tunnel::tunnels.DeleteTunnelPool (m_Pool);		
		if (m_DatagramDestination)
			delete m_DatagramDestination;
	}	

	void ClientDestination::Run ()
	{
		while (m_IsRunning)
		{
			try
			{	
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Destination: runtime exception: ", ex.what ());
			}	
		}	
	}	

	void ClientDestination::Start ()
	{	
		if (!m_IsRunning)
		{	
			m_IsRunning = true;
			m_Pool->SetLocalDestination (shared_from_this ());
			m_Pool->SetActive (true);			
			m_Thread = new std::thread (std::bind (&ClientDestination::Run, this));
			m_StreamingDestination = std::make_shared<i2p::stream::StreamingDestination> (shared_from_this ()); // TODO:
			m_StreamingDestination->Start ();	
			for (auto it: m_StreamingDestinationsByPorts)
				it.second->Start ();
			
			m_CleanupTimer.expires_from_now (boost::posix_time::minutes (DESTINATION_CLEANUP_TIMEOUT));
			m_CleanupTimer.async_wait (std::bind (&ClientDestination::HandleCleanupTimer,
				this, std::placeholders::_1));
		}	
	}
		
	void ClientDestination::Stop ()
	{	
		if (m_IsRunning)
		{	
			m_CleanupTimer.cancel ();
			m_IsRunning = false;
			m_StreamingDestination->Stop ();
			m_StreamingDestination = nullptr;
			for (auto it: m_StreamingDestinationsByPorts)
				it.second->Stop ();
			if (m_DatagramDestination)
			{
				auto d = m_DatagramDestination;
				m_DatagramDestination = nullptr;
				delete d;
			}	
			if (m_Pool)
			{	
				m_Pool->SetLocalDestination (nullptr);
				i2p::tunnel::tunnels.StopTunnelPool (m_Pool);
			}	
			m_Service.stop ();
			if (m_Thread)
			{	
				m_Thread->join (); 
				delete m_Thread;
				m_Thread = 0;
			}	
		}	
	}	

	std::shared_ptr<const i2p::data::LeaseSet> ClientDestination::FindLeaseSet (const i2p::data::IdentHash& ident)
	{
		auto it = m_RemoteLeaseSets.find (ident);
		if (it != m_RemoteLeaseSets.end ())
		{	
			if (!it->second->IsExpired ())
				return it->second;
			else
				LogPrint (eLogWarning, "Destination: remote LeaseSet expired");
		}	
		else
		{	
			auto ls = i2p::data::netdb.FindLeaseSet (ident);
			if (ls)
			{
				ls->PopulateLeases (); // since we don't store them in netdb
				m_RemoteLeaseSets[ident] = ls;			
				return ls;
			}	
		}
		return nullptr;
	}	

	std::shared_ptr<const i2p::data::LeaseSet> ClientDestination::GetLeaseSet ()
	{
		if (!m_Pool) return nullptr;
		if (!m_LeaseSet)
			UpdateLeaseSet ();
		return m_LeaseSet;
	}	

	void ClientDestination::UpdateLeaseSet ()
	{
		m_LeaseSet.reset (new i2p::data::LeaseSet (m_Pool));
	}	

	bool ClientDestination::SubmitSessionKey (const uint8_t * key, const uint8_t * tag)
	{
		struct
		{
			uint8_t k[32], t[32];
		} data;	
		memcpy (data.k, key, 32);
		memcpy (data.t, tag, 32);
		m_Service.post ([this,data](void)
			{
				this->AddSessionKey (data.k, data.t);
			});
		return true;
	}

	void ClientDestination::ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		m_Service.post (std::bind (&ClientDestination::HandleGarlicMessage, this, msg)); 
	}

	void ClientDestination::ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg)
	{
		m_Service.post (std::bind (&ClientDestination::HandleDeliveryStatusMessage, this, msg)); 
	}

	void ClientDestination::HandleI2NPMessage (const uint8_t * buf, size_t len, std::shared_ptr<i2p::tunnel::InboundTunnel> from)
	{
		uint8_t typeID = buf[I2NP_HEADER_TYPEID_OFFSET];
		switch (typeID)
		{	
			case eI2NPData:
				HandleDataMessage (buf + I2NP_HEADER_SIZE, bufbe16toh (buf + I2NP_HEADER_SIZE_OFFSET));
			break;
			case eI2NPDeliveryStatus:
				// we assume tunnel tests non-encrypted
				HandleDeliveryStatusMessage (CreateI2NPMessage (buf, GetI2NPMessageLength (buf), from));
			break;	
			case eI2NPDatabaseStore:
				HandleDatabaseStoreMessage (buf + I2NP_HEADER_SIZE, bufbe16toh (buf + I2NP_HEADER_SIZE_OFFSET));
			break;
			case eI2NPDatabaseSearchReply:
				HandleDatabaseSearchReplyMessage (buf + I2NP_HEADER_SIZE, bufbe16toh (buf + I2NP_HEADER_SIZE_OFFSET));
			break;	
			default:
				i2p::HandleI2NPMessage (CreateI2NPMessage (buf, GetI2NPMessageLength (buf), from));
		}		
	}	

	void ClientDestination::HandleDatabaseStoreMessage (const uint8_t * buf, size_t len)
	{
		uint32_t replyToken = bufbe32toh (buf + DATABASE_STORE_REPLY_TOKEN_OFFSET);
		size_t offset = DATABASE_STORE_HEADER_SIZE;
		if (replyToken) 
		{
			LogPrint (eLogInfo, "Destination: Reply token is ignored for DatabaseStore");
			offset += 36;
		}
		std::shared_ptr<i2p::data::LeaseSet> leaseSet;
		if (buf[DATABASE_STORE_TYPE_OFFSET] == 1) // LeaseSet
		{
			LogPrint (eLogDebug, "Remote LeaseSet");
			auto it = m_RemoteLeaseSets.find (buf + DATABASE_STORE_KEY_OFFSET);
			if (it != m_RemoteLeaseSets.end ())
			{
				leaseSet = it->second;
				leaseSet->Update (buf + offset, len - offset); 
				if (leaseSet->IsValid ())
					LogPrint (eLogDebug, "Remote LeaseSet updated");
				else
				{
					LogPrint (eLogDebug, "Remote LeaseSet update failed");
					m_RemoteLeaseSets.erase (it);
					leaseSet = nullptr;
				}
			}
			else
			{	
				leaseSet = std::make_shared<i2p::data::LeaseSet> (buf + offset, len - offset);
				if (leaseSet->IsValid ())
				{
					LogPrint (eLogDebug, "New remote LeaseSet added");
					m_RemoteLeaseSets[buf + DATABASE_STORE_KEY_OFFSET] = leaseSet;
				}
				else
				{
					LogPrint (eLogError, "New remote LeaseSet verification failed");
					leaseSet = nullptr;
				}
			}	
		}	
		else
			LogPrint (eLogError, "Destination: Unexpected client's DatabaseStore type ", buf[DATABASE_STORE_TYPE_OFFSET], ", dropped");
		
		auto it1 = m_LeaseSetRequests.find (buf + DATABASE_STORE_KEY_OFFSET);
		if (it1 != m_LeaseSetRequests.end ())
		{
			it1->second->requestTimeoutTimer.cancel ();
			if (it1->second->requestComplete) it1->second->requestComplete (leaseSet);
			m_LeaseSetRequests.erase (it1);
		}	
	}

	void ClientDestination::HandleDatabaseSearchReplyMessage (const uint8_t * buf, size_t len)
	{
		i2p::data::IdentHash key (buf);
		int num = buf[32]; // num
		LogPrint (eLogDebug, "Destination: DatabaseSearchReply for ", key.ToBase64 (), " num=", num);
		auto it = m_LeaseSetRequests.find (key);
		if (it != m_LeaseSetRequests.end ())
		{
			auto request = it->second;
			bool found = false;
			if (request->excluded.size () < MAX_NUM_FLOODFILLS_PER_REQUEST)
			{	
				for (int i = 0; i < num; i++)
				{
					i2p::data::IdentHash peerHash (buf + 33 + i*32);
					auto floodfill = i2p::data::netdb.FindRouter (peerHash);
					if (floodfill)
					{
						LogPrint (eLogInfo, "Destination: Requesting ", key.ToBase64 (), " at ", peerHash.ToBase64 ());
						if (SendLeaseSetRequest (key, floodfill, request))
							found = true;
					}	
					else
					{	
						LogPrint (eLogInfo, "Destination: Found new floodfill, request it"); // TODO: recheck this message
						i2p::data::netdb.RequestDestination (peerHash);
					}	
				}
				if (!found)
					LogPrint (eLogError, "Destination: Suggested floodfills are not presented in netDb");
			}	
			else
				LogPrint (eLogInfo, "Destination: ", key.ToBase64 (), " was not found on ", MAX_NUM_FLOODFILLS_PER_REQUEST, " floodfills");
			if (!found)
			{
				if (request->requestComplete) request->requestComplete (nullptr);
				m_LeaseSetRequests.erase (key);
			}	
		}	
		else	
			LogPrint (eLogWarning, "Destination: Request for ", key.ToBase64 (), " not found");
	}	
		
	void ClientDestination::HandleDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg)
	{
		uint32_t msgID = bufbe32toh (msg->GetPayload () + DELIVERY_STATUS_MSGID_OFFSET);
		if (msgID == m_PublishReplyToken)
		{
			LogPrint (eLogDebug, "Destination: Publishing LeaseSet confirmed");
			m_ExcludedFloodfills.clear ();
			m_PublishReplyToken = 0;
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
			LogPrint (eLogError, "Destination: Can't publish non-existing LeaseSet");
			return;
		}
		if (m_PublishReplyToken)
		{
			LogPrint (eLogDebug, "Destination: Publishing LeaseSet is pending");
			return;
		}
		auto outbound = m_Pool->GetNextOutboundTunnel ();
		if (!outbound)
		{
			LogPrint (eLogError, "Destination: Can't publish LeaseSet. No outbound tunnels");
			return;
		}
		std::set<i2p::data::IdentHash> excluded; 
		auto floodfill = i2p::data::netdb.GetClosestFloodfill (m_LeaseSet->GetIdentHash (), m_ExcludedFloodfills);	
		if (!floodfill)
		{
			LogPrint (eLogError, "Destination: Can't publish LeaseSet, no more floodfills found");
			m_ExcludedFloodfills.clear ();
			return;
		}	
		m_ExcludedFloodfills.insert (floodfill->GetIdentHash ());
		LogPrint (eLogDebug, "Destination: Publish LeaseSet of ", GetIdentHash ().ToBase32 ());
		RAND_bytes ((uint8_t *)&m_PublishReplyToken, 4);
		auto msg = WrapMessage (floodfill, i2p::CreateDatabaseStoreMsg (m_LeaseSet, m_PublishReplyToken));			
		m_PublishConfirmationTimer.expires_from_now (boost::posix_time::seconds(PUBLISH_CONFIRMATION_TIMEOUT));
		m_PublishConfirmationTimer.async_wait (std::bind (&ClientDestination::HandlePublishConfirmationTimer,
			this, std::placeholders::_1));	
		outbound->SendTunnelDataMsg (floodfill->GetIdentHash (), 0, msg);	
	}

	void ClientDestination::HandlePublishConfirmationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{	
			if (m_PublishReplyToken)
			{
				LogPrint (eLogWarning, "Destination: Publish confirmation was not received in ", PUBLISH_CONFIRMATION_TIMEOUT,  " seconds, will try again");
				m_PublishReplyToken = 0;
				Publish ();
			}
		}
	}

	void ClientDestination::HandleDataMessage (const uint8_t * buf, size_t len)
	{
		uint32_t length = bufbe32toh (buf);
		buf += 4;
		// we assume I2CP payload
		uint16_t fromPort = bufbe16toh (buf + 4), // source
			toPort = bufbe16toh (buf + 6); // destination 
		switch (buf[9])
		{
			case PROTOCOL_TYPE_STREAMING:
			{
				// streaming protocol
				auto dest = GetStreamingDestination (toPort);
				if (dest)
					dest->HandleDataMessagePayload (buf, length);
				else
					LogPrint (eLogError, "Destination: Missing streaming destination");
			}
			break;
			case PROTOCOL_TYPE_DATAGRAM:
				// datagram protocol
				if (m_DatagramDestination)
					m_DatagramDestination->HandleDataMessagePayload (fromPort, toPort, buf, length);
				else
					LogPrint (eLogError, "Destination: Missing datagram destination");
			break;
			default:
				LogPrint (eLogError, "Destination: Data: unexpected protocol ", buf[9]);
		}
	}	

	void ClientDestination::CreateStream (StreamRequestComplete streamRequestComplete, const i2p::data::IdentHash& dest, int port) {
		assert(streamRequestComplete);
		auto leaseSet = FindLeaseSet (dest);
		if (leaseSet)
			streamRequestComplete(CreateStream (leaseSet, port));
		else
		{
			RequestDestination (dest,
				[this, streamRequestComplete, port](std::shared_ptr<i2p::data::LeaseSet> ls)
				{
					if (ls)
						streamRequestComplete(CreateStream (ls, port));
					else
						streamRequestComplete (nullptr);
				});
		}
	}

	std::shared_ptr<i2p::stream::Stream> ClientDestination::CreateStream (std::shared_ptr<const i2p::data::LeaseSet> remote, int port)
	{
		if (m_StreamingDestination)
			return m_StreamingDestination->CreateNewOutgoingStream (remote, port);
		else
			return nullptr;
	}

	std::shared_ptr<i2p::stream::StreamingDestination> ClientDestination::GetStreamingDestination (int port) const 
	{ 
		if (port) 
		{
			auto it = m_StreamingDestinationsByPorts.find (port);
			if (it != m_StreamingDestinationsByPorts.end ())
				return it->second;
		}	
		// if port is zero or not found, use default destination
		return m_StreamingDestination; 
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

	std::shared_ptr<i2p::stream::StreamingDestination> ClientDestination::CreateStreamingDestination (int port)
	{
		auto dest = std::make_shared<i2p::stream::StreamingDestination> (shared_from_this (), port); 
		if (port)
			m_StreamingDestinationsByPorts[port] = dest;
		else // update default 
			m_StreamingDestination = dest;
		return dest;
	}	
		
	i2p::datagram::DatagramDestination * ClientDestination::CreateDatagramDestination ()
	{
		if (!m_DatagramDestination)
			m_DatagramDestination = new i2p::datagram::DatagramDestination (shared_from_this ());
		return m_DatagramDestination;	
	}

	bool ClientDestination::RequestDestination (const i2p::data::IdentHash& dest, RequestComplete requestComplete)
	{
		if (!m_Pool || !IsReady ()) 
		{	
			if (requestComplete) requestComplete (nullptr);
			return false;
		}	
		m_Service.post (std::bind (&ClientDestination::RequestLeaseSet, shared_from_this (), dest, requestComplete));
		return true;
	}

	void ClientDestination::CancelDestinationRequest (const i2p::data::IdentHash& dest)
	{
		auto s = shared_from_this ();
		m_Service.post ([dest, s](void)
			{
				auto it = s->m_LeaseSetRequests.find (dest);
				if (it != s->m_LeaseSetRequests.end ())
					 s->m_LeaseSetRequests.erase (it);
			});				
	}
		
	void ClientDestination::RequestLeaseSet (const i2p::data::IdentHash& dest, RequestComplete requestComplete)
	{
		std::set<i2p::data::IdentHash> excluded;
		auto floodfill = i2p::data::netdb.GetClosestFloodfill (dest, excluded);
		if (floodfill)
		{
			auto request = std::make_shared<LeaseSetRequest> (m_Service);
			request->requestComplete = requestComplete;
			auto ret = m_LeaseSetRequests.insert (std::pair<i2p::data::IdentHash, std::shared_ptr<LeaseSetRequest> >(dest,request));
			if (ret.second) // inserted
			{
				if (!SendLeaseSetRequest (dest, floodfill, request))
				{
					// request failed
					if (request->requestComplete) request->requestComplete (nullptr);
					m_LeaseSetRequests.erase (dest);
				}
			}	
			else // duplicate
			{
				LogPrint (eLogWarning, "Destination: Request of LeaseSet ", dest.ToBase64 (), " is pending already");
				// TODO: queue up requests
				if (request->requestComplete) request->requestComplete (nullptr);
			}	
		}	
		else
			LogPrint (eLogError, "Destination: Can't request LeaseSet, no floodfills found");
	}	
		
	bool ClientDestination::SendLeaseSetRequest (const i2p::data::IdentHash& dest, 
		std::shared_ptr<const i2p::data::RouterInfo>  nextFloodfill, std::shared_ptr<LeaseSetRequest> request)
	{
		auto replyTunnel = m_Pool->GetNextInboundTunnel ();
		if (!replyTunnel) LogPrint (eLogError, "Destination: Can't send LeaseSet request, no inbound tunnels found");
		
		auto outboundTunnel = m_Pool->GetNextOutboundTunnel ();
		if (!outboundTunnel) LogPrint (eLogError, "Destination: Can't send LeaseSet request, no outbound tunnels found");
			
		if (replyTunnel && outboundTunnel)
		{	
			request->excluded.insert (nextFloodfill->GetIdentHash ());
			request->requestTime = i2p::util::GetSecondsSinceEpoch ();
			request->requestTimeoutTimer.cancel ();

			uint8_t replyKey[32], replyTag[32];
			RAND_bytes (replyKey, 32); // random session key 
			RAND_bytes (replyTag, 32); // random session tag
			AddSessionKey (replyKey, replyTag);

			auto msg = WrapMessage (nextFloodfill,
				CreateLeaseSetDatabaseLookupMsg (dest, request->excluded, 
					replyTunnel.get (), replyKey, replyTag));
			outboundTunnel->SendTunnelDataMsg (
				{
					i2p::tunnel::TunnelMessageBlock 
					{ 
						i2p::tunnel::eDeliveryTypeRouter,
						nextFloodfill->GetIdentHash (), 0, msg
					}
				});	
			request->requestTimeoutTimer.expires_from_now (boost::posix_time::seconds(LEASESET_REQUEST_TIMEOUT));
			request->requestTimeoutTimer.async_wait (std::bind (&ClientDestination::HandleRequestTimoutTimer,
				this, std::placeholders::_1, dest));
		}	
		else
			return false;
		return true;
	}	

	void ClientDestination::HandleRequestTimoutTimer (const boost::system::error_code& ecode, const i2p::data::IdentHash& dest)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto it = m_LeaseSetRequests.find (dest);
			if (it != m_LeaseSetRequests.end ())
			{
				bool done = false;
				uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
				if (ts < it->second->requestTime + MAX_LEASESET_REQUEST_TIMEOUT)
				{
					auto floodfill = i2p::data::netdb.GetClosestFloodfill (dest, it->second->excluded);
					if (floodfill)
						 done = !SendLeaseSetRequest (dest, floodfill, it->second);
					else
						done = true;
				}
				else
				{	
					LogPrint (eLogWarning, "Destination: ", dest.ToBase64 (), " was not found within ",  MAX_LEASESET_REQUEST_TIMEOUT, " seconds");
					done = true;
				}
				
				if (done)
				{
					if (it->second->requestComplete) it->second->requestComplete (nullptr);
					m_LeaseSetRequests.erase (it);
				}	
			}	
		}	
	}

	void ClientDestination::HandleCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			CleanupExpiredTags ();
			CleanupRemoteLeaseSets ();
			m_CleanupTimer.expires_from_now (boost::posix_time::minutes (DESTINATION_CLEANUP_TIMEOUT));
			m_CleanupTimer.async_wait (std::bind (&ClientDestination::HandleCleanupTimer,
				shared_from_this (), std::placeholders::_1));
		}
	}	

	void ClientDestination::CleanupRemoteLeaseSets ()
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto it = m_RemoteLeaseSets.begin (); it != m_RemoteLeaseSets.end ();)
		{
			if (ts > it->second->GetExpirationTime ()) // leaseset expired
			{
				LogPrint (eLogWarning, "Destination: Remote LeaseSet ", it->second->GetIdentHash ().ToBase64 (), " expired");
				it = m_RemoteLeaseSets.erase (it);
			}	
			else 
				it++;
		}
	}

	void ClientDestination::PersistTemporaryKeys ()
	{
		auto path = i2p::util::filesystem::GetDefaultDataDir() / "destinations"; 
		auto filename = path / (GetIdentHash ().ToBase32 () + ".dat");				
		std::ifstream f(filename.string (), std::ifstream::binary);
		if (f)	
		{
			f.read ((char *)m_EncryptionPublicKey, 256);
			f.read ((char *)m_EncryptionPrivateKey, 256);
		}
		if (!f)
		{
			LogPrint (eLogInfo, "Creating new temporary keys for address ", GetIdentHash ().ToBase32 ());
			i2p::crypto::GenerateElGamalKeyPair(m_EncryptionPrivateKey, m_EncryptionPublicKey);
			if (!boost::filesystem::exists (path))
			{
				if (!boost::filesystem::create_directory (path))
					LogPrint (eLogError, "Failed to create destinations directory");
			}
			std::ofstream f1 (filename.string (), std::ofstream::binary | std::ofstream::out);
			if (f1)
			{
				f1.write ((char *)m_EncryptionPublicKey, 256);
				f1.write ((char *)m_EncryptionPrivateKey, 256);
			}
		}	
	}
}
}
