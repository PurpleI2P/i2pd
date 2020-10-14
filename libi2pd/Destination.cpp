/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <algorithm>
#include <cassert>
#include <string>
#include <set>
#include <vector>
#include <boost/algorithm/string.hpp>
#include "Crypto.h"
#include "Config.h"
#include "Log.h"
#include "FS.h"
#include "Timestamp.h"
#include "NetDb.hpp"
#include "Destination.h"

namespace i2p
{
namespace client
{
	LeaseSetDestination::LeaseSetDestination (boost::asio::io_service& service,
		bool isPublic, const std::map<std::string, std::string> * params):
		m_Service (service), m_IsPublic (isPublic), m_PublishReplyToken (0),
		m_LastSubmissionTime (0), m_PublishConfirmationTimer (m_Service),
		m_PublishVerificationTimer (m_Service), m_PublishDelayTimer (m_Service), m_CleanupTimer (m_Service),
		m_LeaseSetType (DEFAULT_LEASESET_TYPE), m_AuthType (i2p::data::ENCRYPTED_LEASESET_AUTH_TYPE_NONE)
	{
		int inLen   = DEFAULT_INBOUND_TUNNEL_LENGTH;
		int inQty   = DEFAULT_INBOUND_TUNNELS_QUANTITY;
		int outLen  = DEFAULT_OUTBOUND_TUNNEL_LENGTH;
		int outQty  = DEFAULT_OUTBOUND_TUNNELS_QUANTITY;
		int numTags = DEFAULT_TAGS_TO_SEND;
		std::shared_ptr<std::vector<i2p::data::IdentHash> > explicitPeers;
		try
		{
			if (params)
			{
				auto it = params->find (I2CP_PARAM_INBOUND_TUNNEL_LENGTH);
				if (it != params->end ())
					inLen = std::stoi(it->second);
				it = params->find (I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH);
				if (it != params->end ())
					outLen = std::stoi(it->second);
				it = params->find (I2CP_PARAM_INBOUND_TUNNELS_QUANTITY);
				if (it != params->end ())
					inQty = std::stoi(it->second);
				it = params->find (I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY);
				if (it != params->end ())
					outQty = std::stoi(it->second);
				it = params->find (I2CP_PARAM_TAGS_TO_SEND);
				if (it != params->end ())
					numTags = std::stoi(it->second);
				LogPrint (eLogInfo, "Destination: parameters for tunnel set to: ", inQty, " inbound (", inLen, " hops), ", outQty, " outbound (", outLen, " hops), ", numTags, " tags");
				it = params->find (I2CP_PARAM_RATCHET_INBOUND_TAGS);
				if (it != params->end ())
					SetNumRatchetInboundTags (std::stoi(it->second));
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
						LogPrint (eLogInfo, "Destination: Added to explicit peers list: ", b64);
					}
				}
				it = params->find (I2CP_PARAM_INBOUND_NICKNAME);
				if (it != params->end ()) m_Nickname = it->second;
				else // try outbound
				{
					it = params->find (I2CP_PARAM_OUTBOUND_NICKNAME);
					if (it != params->end ()) m_Nickname = it->second;
					// otherwise we set default nickname in Start when we know local address
				}
				it = params->find (I2CP_PARAM_LEASESET_TYPE);
				if (it != params->end ())
					m_LeaseSetType = std::stoi(it->second);
				if (m_LeaseSetType == i2p::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2)
				{
					// authentication for encrypted LeaseSet
					it = params->find (I2CP_PARAM_LEASESET_AUTH_TYPE);
					if (it != params->end ())
					{
						auto authType = std::stoi (it->second);
						if (authType >= i2p::data::ENCRYPTED_LEASESET_AUTH_TYPE_NONE && authType <= i2p::data::ENCRYPTED_LEASESET_AUTH_TYPE_PSK)
							m_AuthType = authType;
						else
							LogPrint (eLogError, "Destination: Unknown auth type ", authType);
					}
				}
				it = params->find (I2CP_PARAM_LEASESET_PRIV_KEY);
				if (it != params->end ())
				{
					m_LeaseSetPrivKey.reset (new i2p::data::Tag<32>());
					if (m_LeaseSetPrivKey->FromBase64 (it->second) != 32)
					{
						LogPrint(eLogError, "Destination: invalid value i2cp.leaseSetPrivKey ", it->second);
						m_LeaseSetPrivKey.reset (nullptr);
					}
				}
			}
		}
		catch (std::exception & ex)
		{
			LogPrint(eLogError, "Destination: unable to parse parameters for destination: ", ex.what());
		}
		SetNumTags (numTags);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (inLen, outLen, inQty, outQty);
		if (explicitPeers)
			m_Pool->SetExplicitPeers (explicitPeers);
		if(params)
		{
			auto itr = params->find(I2CP_PARAM_MAX_TUNNEL_LATENCY);
			if (itr != params->end()) {
				auto maxlatency = std::stoi(itr->second);
				itr = params->find(I2CP_PARAM_MIN_TUNNEL_LATENCY);
				if (itr != params->end()) {
					auto minlatency = std::stoi(itr->second);
					if ( minlatency > 0 && maxlatency > 0 ) {
						// set tunnel pool latency
						LogPrint(eLogInfo, "Destination: requiring tunnel latency [", minlatency, "ms, ", maxlatency, "ms]");
						m_Pool->RequireLatency(minlatency, maxlatency);
					}
				}
			}
		}
	}

	LeaseSetDestination::~LeaseSetDestination ()
	{
		if (m_Pool)
			i2p::tunnel::tunnels.DeleteTunnelPool (m_Pool);
		for (auto& it: m_LeaseSetRequests)
			it.second->Complete (nullptr);
	}

	void LeaseSetDestination::Start ()
	{
		if (m_Nickname.empty ())
			m_Nickname = i2p::data::GetIdentHashAbbreviation (GetIdentHash ()); // set default nickname
		LoadTags ();
		m_Pool->SetLocalDestination (shared_from_this ());
		m_Pool->SetActive (true);
		m_CleanupTimer.expires_from_now (boost::posix_time::minutes (DESTINATION_CLEANUP_TIMEOUT));
		m_CleanupTimer.async_wait (std::bind (&LeaseSetDestination::HandleCleanupTimer,
			shared_from_this (), std::placeholders::_1));
	}

	void LeaseSetDestination::Stop ()
	{
		m_CleanupTimer.cancel ();
		m_PublishConfirmationTimer.cancel ();
		m_PublishVerificationTimer.cancel ();
		if (m_Pool)
		{
			m_Pool->SetLocalDestination (nullptr);
			i2p::tunnel::tunnels.StopTunnelPool (m_Pool);
		}
		SaveTags ();
		CleanUp (); // GarlicDestination
	}

	bool LeaseSetDestination::Reconfigure(std::map<std::string, std::string> params)
	{
		auto itr = params.find("i2cp.dontPublishLeaseSet");
		if (itr != params.end())
		{
			m_IsPublic = itr->second != "true";
		}

		int inLen, outLen, inQuant, outQuant, numTags, minLatency, maxLatency;
		std::map<std::string, int&> intOpts = {
			{I2CP_PARAM_INBOUND_TUNNEL_LENGTH, inLen},
			{I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH, outLen},
			{I2CP_PARAM_INBOUND_TUNNELS_QUANTITY, inQuant},
			{I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY, outQuant},
			{I2CP_PARAM_TAGS_TO_SEND, numTags},
			{I2CP_PARAM_MIN_TUNNEL_LATENCY, minLatency},
			{I2CP_PARAM_MAX_TUNNEL_LATENCY, maxLatency}
		};

		auto pool = GetTunnelPool();
		inLen = pool->GetNumInboundHops();
		outLen = pool->GetNumOutboundHops();
		inQuant = pool->GetNumInboundTunnels();
		outQuant = pool->GetNumOutboundTunnels();
		minLatency = 0;
		maxLatency = 0;

		for (auto & opt : intOpts)
		{
			itr = params.find(opt.first);
			if(itr != params.end())
			{
				opt.second = std::stoi(itr->second);
			}
		}
		pool->RequireLatency(minLatency, maxLatency);
		return pool->Reconfigure(inLen, outLen, inQuant, outQuant);
	}

	std::shared_ptr<i2p::data::LeaseSet> LeaseSetDestination::FindLeaseSet (const i2p::data::IdentHash& ident)
	{
		std::shared_ptr<i2p::data::LeaseSet> remoteLS;
		{
			std::lock_guard<std::mutex> lock(m_RemoteLeaseSetsMutex);
			auto it = m_RemoteLeaseSets.find (ident);
			if (it != m_RemoteLeaseSets.end ())
				remoteLS = it->second;
		}

		if (remoteLS)
		{
			if (!remoteLS->IsExpired ())
			{
				if (remoteLS->ExpiresSoon())
				{
					LogPrint(eLogDebug, "Destination: Lease Set expires soon, updating before expire");
					// update now before expiration for smooth handover
					auto s = shared_from_this ();
					RequestDestination(ident, [s, ident] (std::shared_ptr<i2p::data::LeaseSet> ls) {
						if(ls && !ls->IsExpired())
						{
							ls->PopulateLeases();
							{
								std::lock_guard<std::mutex> _lock(s->m_RemoteLeaseSetsMutex);
								s->m_RemoteLeaseSets[ident] = ls;
							}
						}
					});
				}
				return remoteLS;
			}
			else
			{
				LogPrint (eLogWarning, "Destination: remote LeaseSet expired");
				std::lock_guard<std::mutex> lock(m_RemoteLeaseSetsMutex);
				m_RemoteLeaseSets.erase (ident);
				return nullptr;
			}
		}
		else
		{
			auto ls = i2p::data::netdb.FindLeaseSet (ident);
			if (ls && !ls->IsExpired ())
			{
				ls->PopulateLeases (); // since we don't store them in netdb
				std::lock_guard<std::mutex> _lock(m_RemoteLeaseSetsMutex);
				m_RemoteLeaseSets[ident] = ls;
				return ls;
			}
		}
		return nullptr;
	}

	std::shared_ptr<const i2p::data::LocalLeaseSet> LeaseSetDestination::GetLeaseSet ()
	{
		if (!m_Pool) return nullptr;
		if (!m_LeaseSet)
			UpdateLeaseSet ();
		auto ls = GetLeaseSetMt ();
		return (ls && ls->GetInnerLeaseSet ()) ? ls->GetInnerLeaseSet () : ls; // always non-encrypted
	}

	std::shared_ptr<const i2p::data::LocalLeaseSet> LeaseSetDestination::GetLeaseSetMt ()
	{
		std::lock_guard<std::mutex> l(m_LeaseSetMutex);
		return m_LeaseSet;
	}

	void LeaseSetDestination::SetLeaseSet (std::shared_ptr<const i2p::data::LocalLeaseSet> newLeaseSet)
	{
		{
			std::lock_guard<std::mutex> l(m_LeaseSetMutex);
			m_LeaseSet = newLeaseSet;
		}
		i2p::garlic::GarlicDestination::SetLeaseSetUpdated ();
		if (m_IsPublic)
		{
			auto s = shared_from_this ();
			m_Service.post ([s](void)
			{
				s->m_PublishVerificationTimer.cancel ();
				s->Publish ();
			});
		}
	}

	void LeaseSetDestination::UpdateLeaseSet ()
	{
		int numTunnels = m_Pool->GetNumInboundTunnels () + 2; // 2 backup tunnels
		if (numTunnels > i2p::data::MAX_NUM_LEASES) numTunnels = i2p::data::MAX_NUM_LEASES; // 16 tunnels maximum
		CreateNewLeaseSet (m_Pool->GetInboundTunnels (numTunnels));
	}

	bool LeaseSetDestination::SubmitSessionKey (const uint8_t * key, const uint8_t * tag)
	{
		struct
		{
			uint8_t k[32], t[32];
		} data;
		memcpy (data.k, key, 32);
		memcpy (data.t, tag, 32);
		auto s = shared_from_this ();
		m_Service.post ([s,data](void)
			{
				s->AddSessionKey (data.k, data.t);
			});
		return true;
	}

	void LeaseSetDestination::ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		m_Service.post (std::bind (&LeaseSetDestination::HandleGarlicMessage, shared_from_this (), msg));
	}

	void LeaseSetDestination::ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg)
	{
		uint32_t msgID = bufbe32toh (msg->GetPayload () + DELIVERY_STATUS_MSGID_OFFSET);
		m_Service.post (std::bind (&LeaseSetDestination::HandleDeliveryStatusMessage, shared_from_this (), msgID));
	}

	void LeaseSetDestination::HandleI2NPMessage (const uint8_t * buf, size_t len)
	{
		I2NPMessageType typeID = (I2NPMessageType)(buf[I2NP_HEADER_TYPEID_OFFSET]);
		LeaseSetDestination::HandleCloveI2NPMessage (typeID, buf + I2NP_HEADER_SIZE, GetI2NPMessageLength(buf, len) - I2NP_HEADER_SIZE);
	}

	bool LeaseSetDestination::HandleCloveI2NPMessage (I2NPMessageType typeID, const uint8_t * payload, size_t len)
	{
		switch (typeID)
		{
			case eI2NPData:
				HandleDataMessage (payload, len);
			break;
			case eI2NPDeliveryStatus:
				// we assume tunnel tests non-encrypted
				HandleDeliveryStatusMessage (bufbe32toh (payload + DELIVERY_STATUS_MSGID_OFFSET));
			break;
			case eI2NPDatabaseStore:
				HandleDatabaseStoreMessage (payload, len);
			break;
			case eI2NPDatabaseSearchReply:
				HandleDatabaseSearchReplyMessage (payload, len);
			break;
			default:
				LogPrint (eLogWarning, "Destination: Unexpected I2NP message type ", typeID);
				return false;
		}
		return true;
	}

	void LeaseSetDestination::HandleDatabaseStoreMessage (const uint8_t * buf, size_t len)
	{
		uint32_t replyToken = bufbe32toh (buf + DATABASE_STORE_REPLY_TOKEN_OFFSET);
		size_t offset = DATABASE_STORE_HEADER_SIZE;
		if (replyToken)
		{
			LogPrint (eLogInfo, "Destination: Reply token is ignored for DatabaseStore");
			offset += 36;
		}
		i2p::data::IdentHash key (buf + DATABASE_STORE_KEY_OFFSET);
		std::shared_ptr<i2p::data::LeaseSet> leaseSet;
		switch (buf[DATABASE_STORE_TYPE_OFFSET])
		{
			case i2p::data::NETDB_STORE_TYPE_LEASESET: // 1
			case i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2: // 3
			{
				LogPrint (eLogDebug, "Destination: Remote LeaseSet");
				std::lock_guard<std::mutex> lock(m_RemoteLeaseSetsMutex);
				auto it = m_RemoteLeaseSets.find (key);
				if (it != m_RemoteLeaseSets.end ())
				{
					leaseSet = it->second;
					if (leaseSet->IsNewer (buf + offset, len - offset))
					{
						leaseSet->Update (buf + offset, len - offset);
						if (leaseSet->IsValid () && leaseSet->GetIdentHash () == key)
							LogPrint (eLogDebug, "Destination: Remote LeaseSet updated");
						else
						{
							LogPrint (eLogDebug, "Destination: Remote LeaseSet update failed");
							m_RemoteLeaseSets.erase (it);
							leaseSet = nullptr;
						}
					}
					else
						LogPrint (eLogDebug, "Destination: Remote LeaseSet is older. Not updated");
				}
				else
				{
					if (buf[DATABASE_STORE_TYPE_OFFSET] == i2p::data::NETDB_STORE_TYPE_LEASESET)
						leaseSet = std::make_shared<i2p::data::LeaseSet> (buf + offset, len - offset); // LeaseSet
					else
						leaseSet = std::make_shared<i2p::data::LeaseSet2> (buf[DATABASE_STORE_TYPE_OFFSET], buf + offset, len - offset, true, GetPreferredCryptoType () ); // LeaseSet2
					if (leaseSet->IsValid () && leaseSet->GetIdentHash () == key)
					{
						if (leaseSet->GetIdentHash () != GetIdentHash ())
						{
							LogPrint (eLogDebug, "Destination: New remote LeaseSet added");
							m_RemoteLeaseSets[key] = leaseSet;
						}
						else
							LogPrint (eLogDebug, "Destination: Own remote LeaseSet dropped");
					}
					else
					{
						LogPrint (eLogError, "Destination: New remote LeaseSet failed");
						leaseSet = nullptr;
					}
				}
				break;
			}
			case i2p::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2: // 5
			{
				auto it2 = m_LeaseSetRequests.find (key);
				if (it2 != m_LeaseSetRequests.end () && it2->second->requestedBlindedKey)
				{
					auto ls2 = std::make_shared<i2p::data::LeaseSet2> (buf + offset, len - offset,
						it2->second->requestedBlindedKey, m_LeaseSetPrivKey ? ((const uint8_t *)*m_LeaseSetPrivKey) : nullptr , GetPreferredCryptoType ());
					if (ls2->IsValid ())
					{
						m_RemoteLeaseSets[ls2->GetIdentHash ()] = ls2; // ident is not key
						m_RemoteLeaseSets[key] = ls2; // also store as key for next lookup
						leaseSet = ls2;
					}
				}
				else
					LogPrint (eLogInfo, "Destination: Couldn't find request for encrypted LeaseSet2");
				break;
			}
			default:
				LogPrint (eLogError, "Destination: Unexpected client's DatabaseStore type ", buf[DATABASE_STORE_TYPE_OFFSET], ", dropped");
		}

		auto it1 = m_LeaseSetRequests.find (key);
		if (it1 != m_LeaseSetRequests.end ())
		{
			it1->second->requestTimeoutTimer.cancel ();
			if (it1->second) it1->second->Complete (leaseSet);
			m_LeaseSetRequests.erase (it1);
		}
	}

	void LeaseSetDestination::HandleDatabaseSearchReplyMessage (const uint8_t * buf, size_t len)
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
					if (!request->excluded.count (peerHash) && !i2p::data::netdb.FindRouter (peerHash))
					{
						LogPrint (eLogInfo, "Destination: Found new floodfill, request it"); 
						i2p::data::netdb.RequestDestination (peerHash, nullptr, false); // through exploratory
					}
				}

				auto floodfill = i2p::data::netdb.GetClosestFloodfill (key, request->excluded);
				if (floodfill)
				{
					LogPrint (eLogInfo, "Destination: Requesting ", key.ToBase64 (), " at ", floodfill->GetIdentHash ().ToBase64 ());
					if (SendLeaseSetRequest (key, floodfill, request))
						found = true;
				}
			}
			if (!found)
			{
				LogPrint (eLogInfo, "Destination: ", key.ToBase64 (), " was not found on ", MAX_NUM_FLOODFILLS_PER_REQUEST, " floodfills");
				request->Complete (nullptr);
				m_LeaseSetRequests.erase (key);
			}
		}
		else
			LogPrint (eLogWarning, "Destination: Request for ", key.ToBase64 (), " not found");
	}

	void LeaseSetDestination::HandleDeliveryStatusMessage (uint32_t msgID)
	{
		if (msgID == m_PublishReplyToken)
		{
			LogPrint (eLogDebug, "Destination: Publishing LeaseSet confirmed for ", GetIdentHash().ToBase32());
			m_ExcludedFloodfills.clear ();
			m_PublishReplyToken = 0;
			// schedule verification
			m_PublishVerificationTimer.expires_from_now (boost::posix_time::seconds(PUBLISH_VERIFICATION_TIMEOUT));
			m_PublishVerificationTimer.async_wait (std::bind (&LeaseSetDestination::HandlePublishVerificationTimer,
			shared_from_this (), std::placeholders::_1));
		}
		else
			i2p::garlic::GarlicDestination::HandleDeliveryStatusMessage (msgID);
	}

	void LeaseSetDestination::SetLeaseSetUpdated ()
	{
		UpdateLeaseSet ();
	}

	void LeaseSetDestination::Publish ()
	{
		auto leaseSet = GetLeaseSetMt ();
		if (!leaseSet || !m_Pool)
		{
			LogPrint (eLogError, "Destination: Can't publish non-existing LeaseSet");
			return;
		}
		if (m_PublishReplyToken)
		{
			LogPrint (eLogDebug, "Destination: Publishing LeaseSet is pending");
			return;
		}
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		if (ts < m_LastSubmissionTime + PUBLISH_MIN_INTERVAL)
		{
			LogPrint (eLogDebug, "Destination: Publishing LeaseSet is too fast. Wait for ", PUBLISH_MIN_INTERVAL, " seconds");
			m_PublishDelayTimer.cancel ();
			m_PublishDelayTimer.expires_from_now (boost::posix_time::seconds(PUBLISH_MIN_INTERVAL));
			m_PublishDelayTimer.async_wait (std::bind (&LeaseSetDestination::HandlePublishDelayTimer,
				shared_from_this (), std::placeholders::_1));
			return;
		}
		auto outbound = m_Pool->GetNextOutboundTunnel ();
		if (!outbound)
		{
			LogPrint (eLogError, "Destination: Can't publish LeaseSet. No outbound tunnels");
			return;
		}
		auto inbound = m_Pool->GetNextInboundTunnel ();
		if (!inbound)
		{
			LogPrint (eLogError, "Destination: Can't publish LeaseSet. No inbound tunnels");
			return;
		}
		auto floodfill = i2p::data::netdb.GetClosestFloodfill (leaseSet->GetIdentHash (), m_ExcludedFloodfills);
		if (!floodfill)
		{
			LogPrint (eLogError, "Destination: Can't publish LeaseSet, no more floodfills found");
			m_ExcludedFloodfills.clear ();
			return;
		}
		m_ExcludedFloodfills.insert (floodfill->GetIdentHash ());
		LogPrint (eLogDebug, "Destination: Publish LeaseSet of ", GetIdentHash ().ToBase32 ());
		RAND_bytes ((uint8_t *)&m_PublishReplyToken, 4);
		auto msg = WrapMessage (floodfill, i2p::CreateDatabaseStoreMsg (leaseSet, m_PublishReplyToken, inbound));
		m_PublishConfirmationTimer.expires_from_now (boost::posix_time::seconds(PUBLISH_CONFIRMATION_TIMEOUT));
		m_PublishConfirmationTimer.async_wait (std::bind (&LeaseSetDestination::HandlePublishConfirmationTimer,
			shared_from_this (), std::placeholders::_1));
		outbound->SendTunnelDataMsg (floodfill->GetIdentHash (), 0, msg);
		m_LastSubmissionTime = ts;
	}

	void LeaseSetDestination::HandlePublishConfirmationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			if (m_PublishReplyToken)
			{
				m_PublishReplyToken = 0;
				if (GetIdentity ()->GetCryptoKeyType () == i2p::data::CRYPTO_KEY_TYPE_ELGAMAL)
				{
					LogPrint (eLogWarning, "Destination: Publish confirmation was not received in ", PUBLISH_CONFIRMATION_TIMEOUT, " seconds, will try again");
					Publish ();
				}
				else
				{
					LogPrint (eLogWarning, "Destination: Publish confirmation was not received in ", PUBLISH_CONFIRMATION_TIMEOUT, " seconds from Java floodfill for crypto type ", (int)GetIdentity ()->GetCryptoKeyType ());
					// Java floodfill never sends confirmation back for unknown crypto type
					// assume it successive and try to verify
					m_PublishVerificationTimer.expires_from_now (boost::posix_time::seconds(PUBLISH_VERIFICATION_TIMEOUT));
					m_PublishVerificationTimer.async_wait (std::bind (&LeaseSetDestination::HandlePublishVerificationTimer,
			shared_from_this (), std::placeholders::_1));

				}
			}
		}
	}

	void LeaseSetDestination::HandlePublishVerificationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ls = GetLeaseSetMt ();
			if (!ls)
			{
				LogPrint (eLogWarning, "Destination: couldn't verify LeaseSet for ", GetIdentHash().ToBase32());
				return;
			}
			auto s = shared_from_this ();
			RequestLeaseSet (ls->GetStoreHash (),
				[s, ls](std::shared_ptr<const i2p::data::LeaseSet> leaseSet)
				{
					if (leaseSet)
					{
						if (*ls == *leaseSet)
						{
							// we got latest LeasetSet
							LogPrint (eLogDebug, "Destination: published LeaseSet verified for ", s->GetIdentHash().ToBase32());
							s->m_PublishVerificationTimer.expires_from_now (boost::posix_time::seconds(PUBLISH_REGULAR_VERIFICATION_INTERNAL));
							s->m_PublishVerificationTimer.async_wait (std::bind (&LeaseSetDestination::HandlePublishVerificationTimer, s, std::placeholders::_1));
							return;
						}
						else
							LogPrint (eLogDebug, "Destination: LeaseSet is different than just published for ", s->GetIdentHash().ToBase32());
					}
					else
						LogPrint (eLogWarning, "Destination: couldn't find published LeaseSet for ", s->GetIdentHash().ToBase32());
					// we have to publish again
					s->Publish ();
				});
		}
	}

	void LeaseSetDestination::HandlePublishDelayTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
			Publish ();
	}

	bool LeaseSetDestination::RequestDestination (const i2p::data::IdentHash& dest, RequestComplete requestComplete)
	{
		if (!m_Pool || !IsReady ())
		{
			if (requestComplete)
				m_Service.post ([requestComplete](void){requestComplete (nullptr);});
			return false;
		}
		m_Service.post (std::bind (&LeaseSetDestination::RequestLeaseSet, shared_from_this (), dest, requestComplete, nullptr));
		return true;
	}

	bool LeaseSetDestination::RequestDestinationWithEncryptedLeaseSet (std::shared_ptr<const i2p::data::BlindedPublicKey> dest, RequestComplete requestComplete)
	{
		if (!dest || !m_Pool || !IsReady ())
		{
			if (requestComplete)
				m_Service.post ([requestComplete](void){requestComplete (nullptr);});
			return false;
		}
		auto storeHash = dest->GetStoreHash ();
		auto leaseSet = FindLeaseSet (storeHash);
		if (leaseSet)
		{
			if (requestComplete)
				m_Service.post ([requestComplete, leaseSet](void){requestComplete (leaseSet);});
			return true;
		}
		m_Service.post (std::bind (&LeaseSetDestination::RequestLeaseSet, shared_from_this (), storeHash, requestComplete, dest));
		return true;
	}

	void LeaseSetDestination::CancelDestinationRequest (const i2p::data::IdentHash& dest, bool notify)
	{
		auto s = shared_from_this ();
		m_Service.post ([dest, notify, s](void)
			{
				auto it = s->m_LeaseSetRequests.find (dest);
				if (it != s->m_LeaseSetRequests.end ())
				{
					auto requestComplete = it->second;
					s->m_LeaseSetRequests.erase (it);
					if (notify && requestComplete) requestComplete->Complete (nullptr);
				}
			});
	}

	void LeaseSetDestination::CancelDestinationRequestWithEncryptedLeaseSet (std::shared_ptr<const i2p::data::BlindedPublicKey> dest, bool notify)
	{
		if (dest)
			CancelDestinationRequest (dest->GetStoreHash (), notify);
	}

	void LeaseSetDestination::RequestLeaseSet (const i2p::data::IdentHash& dest, RequestComplete requestComplete, std::shared_ptr<const i2p::data::BlindedPublicKey> requestedBlindedKey)
	{
		std::set<i2p::data::IdentHash> excluded;
		auto floodfill = i2p::data::netdb.GetClosestFloodfill (dest, excluded);
		if (floodfill)
		{
			auto request = std::make_shared<LeaseSetRequest> (m_Service);
			request->requestedBlindedKey = requestedBlindedKey; // for encrypted LeaseSet2
			if (requestComplete)
				request->requestComplete.push_back (requestComplete);
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			auto ret = m_LeaseSetRequests.insert (std::pair<i2p::data::IdentHash, std::shared_ptr<LeaseSetRequest> >(dest,request));
			if (ret.second) // inserted
			{
				request->requestTime = ts;
				if (!SendLeaseSetRequest (dest, floodfill, request))
				{
					// request failed
					m_LeaseSetRequests.erase (ret.first);
					if (requestComplete) requestComplete (nullptr);
				}
			}
			else // duplicate
			{
				LogPrint (eLogInfo, "Destination: Request of LeaseSet ", dest.ToBase64 (), " is pending already");
				if (ts > ret.first->second->requestTime + MAX_LEASESET_REQUEST_TIMEOUT)
				{
					// something went wrong
					m_LeaseSetRequests.erase (ret.first);
					if (requestComplete) requestComplete (nullptr);
				}
				else if (requestComplete)
					ret.first->second->requestComplete.push_back (requestComplete);
			}
		}
		else
		{
			LogPrint (eLogError, "Destination: Can't request LeaseSet, no floodfills found");
			if (requestComplete) requestComplete (nullptr);
		}
	}

	bool LeaseSetDestination::SendLeaseSetRequest (const i2p::data::IdentHash& dest,
		std::shared_ptr<const i2p::data::RouterInfo> nextFloodfill, std::shared_ptr<LeaseSetRequest> request)
	{
		if (!request->replyTunnel || !request->replyTunnel->IsEstablished ())
			request->replyTunnel = m_Pool->GetNextInboundTunnel ();
		if (!request->replyTunnel) LogPrint (eLogError, "Destination: Can't send LeaseSet request, no inbound tunnels found");
		if (!request->outboundTunnel || !request->outboundTunnel->IsEstablished ())
			request->outboundTunnel = m_Pool->GetNextOutboundTunnel ();
		if (!request->outboundTunnel) LogPrint (eLogError, "Destination: Can't send LeaseSet request, no outbound tunnels found");

		if (request->replyTunnel && request->outboundTunnel)
		{
			request->excluded.insert (nextFloodfill->GetIdentHash ());
			request->requestTimeoutTimer.cancel ();

			bool isECIES = SupportsEncryptionType (i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET) &&
				nextFloodfill->GetVersion () >= MAKE_VERSION_NUMBER(0, 9, 46); // >= 0.9.46;
			uint8_t replyKey[32], replyTag[32];
			RAND_bytes (replyKey, 32); // random session key
			RAND_bytes (replyTag, isECIES ? 8 : 32); // random session tag
			if (isECIES)	
				AddECIESx25519Key (replyKey, replyTag);
			else	
				AddSessionKey (replyKey, replyTag);

			auto msg = WrapMessage (nextFloodfill,
				CreateLeaseSetDatabaseLookupMsg (dest, request->excluded,
					request->replyTunnel, replyKey, replyTag, isECIES));
			request->outboundTunnel->SendTunnelDataMsg (
				{
					i2p::tunnel::TunnelMessageBlock
					{
						i2p::tunnel::eDeliveryTypeRouter,
						nextFloodfill->GetIdentHash (), 0, msg
					}
				});
			request->requestTimeoutTimer.expires_from_now (boost::posix_time::seconds(LEASESET_REQUEST_TIMEOUT));
			request->requestTimeoutTimer.async_wait (std::bind (&LeaseSetDestination::HandleRequestTimoutTimer,
				shared_from_this (), std::placeholders::_1, dest));
		}
		else
			return false;
		return true;
	}

	void LeaseSetDestination::HandleRequestTimoutTimer (const boost::system::error_code& ecode, const i2p::data::IdentHash& dest)
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
					{
						// reset tunnels, because one them might fail
						it->second->outboundTunnel = nullptr;
						it->second->replyTunnel = nullptr;
						done = !SendLeaseSetRequest (dest, floodfill, it->second);
					}
					else
						done = true;
				}
				else
				{
					LogPrint (eLogWarning, "Destination: ", dest.ToBase64 (), " was not found within ", MAX_LEASESET_REQUEST_TIMEOUT, " seconds");
					done = true;
				}

				if (done)
				{
					auto requestComplete = it->second;
					m_LeaseSetRequests.erase (it);
					if (requestComplete) requestComplete->Complete (nullptr);
				}
			}
		}
	}

	void LeaseSetDestination::HandleCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			CleanupExpiredTags ();
			CleanupRemoteLeaseSets ();
			CleanupDestination ();
			m_CleanupTimer.expires_from_now (boost::posix_time::minutes (DESTINATION_CLEANUP_TIMEOUT));
			m_CleanupTimer.async_wait (std::bind (&LeaseSetDestination::HandleCleanupTimer,
				shared_from_this (), std::placeholders::_1));
		}
	}

	void LeaseSetDestination::CleanupRemoteLeaseSets ()
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		std::lock_guard<std::mutex> lock(m_RemoteLeaseSetsMutex);
		for (auto it = m_RemoteLeaseSets.begin (); it != m_RemoteLeaseSets.end ();)
		{
			if (it->second->IsEmpty () || ts > it->second->GetExpirationTime ()) // leaseset expired
			{
				LogPrint (eLogWarning, "Destination: Remote LeaseSet ", it->second->GetIdentHash ().ToBase64 (), " expired");
				it = m_RemoteLeaseSets.erase (it);
			}
			else
				++it;
		}
	}

	i2p::data::CryptoKeyType LeaseSetDestination::GetPreferredCryptoType () const
	{
		if (SupportsEncryptionType (i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET))
			return i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET;
		return i2p::data::CRYPTO_KEY_TYPE_ELGAMAL;
	}

	ClientDestination::ClientDestination (boost::asio::io_service& service, const i2p::data::PrivateKeys& keys,
		bool isPublic, const std::map<std::string, std::string> * params):
		LeaseSetDestination (service, isPublic, params), 
		m_Keys (keys), m_StreamingAckDelay (DEFAULT_INITIAL_ACK_DELAY), 
		m_IsStreamingAnswerPings (DEFAULT_ANSWER_PINGS),
		m_DatagramDestination (nullptr), m_RefCounter (0),
		m_ReadyChecker(service)
	{
		if (keys.IsOfflineSignature () && GetLeaseSetType () == i2p::data::NETDB_STORE_TYPE_LEASESET)
			SetLeaseSetType (i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2); // offline keys can be published with LS2 only

		// extract encryption type params for LS2
		std::set<i2p::data::CryptoKeyType> encryptionKeyTypes;
		if (params)
		{
			auto it = params->find (I2CP_PARAM_LEASESET_ENCRYPTION_TYPE);
			if (it != params->end ())
			{
				// comma-separated values
				std::vector<std::string> values;
				boost::split(values, it->second, boost::is_any_of(","));
				for (auto& it1: values)
				{
					try
					{
						encryptionKeyTypes.insert (std::stoi(it1));
					}
					catch (std::exception& ex)
					{
						LogPrint (eLogInfo, "Destination: Unexpected crypto type ", it1, ". ", ex.what ());
						continue;
					}
				}
			}
		}
		// if no param or valid crypto type use from identity
		bool isSingleKey = false;
		if (encryptionKeyTypes.empty ())
		{
			isSingleKey = true;
			encryptionKeyTypes.insert (GetIdentity ()->GetCryptoKeyType ());
		}

		for (auto& it: encryptionKeyTypes)
		{
			auto encryptionKey = new EncryptionKey (it);
			if (isPublic)
				PersistTemporaryKeys (encryptionKey, isSingleKey);
			else
				encryptionKey->GenerateKeys ();
			encryptionKey->CreateDecryptor ();
			if (it == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET)
			{	
				m_ECIESx25519EncryptionKey.reset (encryptionKey);
				if (GetLeaseSetType () == i2p::data::NETDB_STORE_TYPE_LEASESET)
					SetLeaseSetType (i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2); // Rathets must use LeaseSet2 
			}	
			else
				m_StandardEncryptionKey.reset (encryptionKey);
		}

		if (isPublic)
			LogPrint (eLogInfo, "Destination: Local address ", GetIdentHash().ToBase32 (), " created");

		try
		{
			if (params)
			{
				// extract streaming params
				auto it = params->find (I2CP_PARAM_STREAMING_INITIAL_ACK_DELAY);
				if (it != params->end ())
					m_StreamingAckDelay = std::stoi(it->second);
				it = params->find (I2CP_PARAM_STREAMING_ANSWER_PINGS);
				if (it != params->end ())
					i2p::config::GetOption (it->second, m_IsStreamingAnswerPings);
				
				if (GetLeaseSetType () == i2p::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2)
				{
					// authentication for encrypted LeaseSet
					auto authType = GetAuthType ();
					if (authType > 0)
					{
						m_AuthKeys = std::make_shared<std::vector<i2p::data::AuthPublicKey> >();
						if (authType == i2p::data::ENCRYPTED_LEASESET_AUTH_TYPE_DH)
							ReadAuthKey (I2CP_PARAM_LEASESET_CLIENT_DH, params);
						else if (authType == i2p::data::ENCRYPTED_LEASESET_AUTH_TYPE_PSK)
							ReadAuthKey (I2CP_PARAM_LEASESET_CLIENT_PSK, params);
						else
							LogPrint (eLogError, "Destination: Unexpected auth type ", authType);
						if (m_AuthKeys->size ())
							LogPrint (eLogInfo, "Destination: ", m_AuthKeys->size (), " auth keys read");
						else
						{
							LogPrint (eLogError, "Destination: No auth keys read for auth type ", authType);
							m_AuthKeys = nullptr;
						}
					}
				}
			}
		}
		catch (std::exception & ex)
		{
			LogPrint(eLogError, "Destination: unable to parse parameters for destination: ", ex.what());
		}
	}

	ClientDestination::~ClientDestination ()
	{
	}

	void ClientDestination::Start ()
	{
		LeaseSetDestination::Start ();
		m_StreamingDestination = std::make_shared<i2p::stream::StreamingDestination> (GetSharedFromThis ()); // TODO:
		m_StreamingDestination->Start ();
		for (auto& it: m_StreamingDestinationsByPorts)
			it.second->Start ();
	}

	void ClientDestination::Stop ()
	{
		LeaseSetDestination::Stop ();
		m_ReadyChecker.cancel();
		m_StreamingDestination->Stop ();
		//m_StreamingDestination->SetOwner (nullptr);
		m_StreamingDestination = nullptr;
		for (auto& it: m_StreamingDestinationsByPorts)
		{
			it.second->Stop ();
			//it.second->SetOwner (nullptr);
		}
		m_StreamingDestinationsByPorts.clear ();
		if (m_DatagramDestination)
		{
			delete m_DatagramDestination;
			m_DatagramDestination = nullptr;
		}
	}

	void ClientDestination::HandleDataMessage (const uint8_t * buf, size_t len)
	{
		uint32_t length = bufbe32toh (buf);
		if(length > len - 4)
		{
			LogPrint(eLogError, "Destination: Data message length ", length, " exceeds buffer length ", len);
			return;
		}
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
			case PROTOCOL_TYPE_RAW:
				// raw datagram
				if (m_DatagramDestination)
					m_DatagramDestination->HandleDataMessagePayload (fromPort, toPort, buf, length, true);
				else
					LogPrint (eLogError, "Destination: Missing raw datagram destination");
			break;
			default:
				LogPrint (eLogError, "Destination: Data: unexpected protocol ", buf[9]);
		}
	}

	void ClientDestination::CreateStream (StreamRequestComplete streamRequestComplete, const i2p::data::IdentHash& dest, int port)
	{
		if (!streamRequestComplete)
		{
			LogPrint (eLogError, "Destination: request callback is not specified in CreateStream");
			return;
		}
		auto leaseSet = FindLeaseSet (dest);
		if (leaseSet)
			streamRequestComplete(CreateStream (leaseSet, port));
		else
		{
			auto s = GetSharedFromThis ();
			RequestDestination (dest,
				[s, streamRequestComplete, port](std::shared_ptr<const i2p::data::LeaseSet> ls)
				{
					if (ls)
						streamRequestComplete(s->CreateStream (ls, port));
					else
						streamRequestComplete (nullptr);
				});
		}
	}

	void ClientDestination::CreateStream (StreamRequestComplete streamRequestComplete, std::shared_ptr<const i2p::data::BlindedPublicKey> dest, int port)
	{
		if (!streamRequestComplete)
		{
			LogPrint (eLogError, "Destination: request callback is not specified in CreateStream");
			return;
		}
		auto s = GetSharedFromThis ();
		RequestDestinationWithEncryptedLeaseSet (dest,
			[s, streamRequestComplete, port](std::shared_ptr<i2p::data::LeaseSet> ls)
			{
				if (ls)
					streamRequestComplete(s->CreateStream (ls, port));
				else
					streamRequestComplete (nullptr);
			});
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

	void ClientDestination::AcceptOnce (const i2p::stream::StreamingDestination::Acceptor& acceptor)
	{
		if (m_StreamingDestination)
			m_StreamingDestination->AcceptOnce (acceptor);
	}

	std::shared_ptr<i2p::stream::StreamingDestination> ClientDestination::CreateStreamingDestination (int port, bool gzip)
	{
		auto dest = std::make_shared<i2p::stream::StreamingDestination> (GetSharedFromThis (), port, gzip);
		if (port)
			m_StreamingDestinationsByPorts[port] = dest;
		else // update default
			m_StreamingDestination = dest;
		return dest;
	}

	i2p::datagram::DatagramDestination * ClientDestination::CreateDatagramDestination (bool gzip)
	{
		if (m_DatagramDestination == nullptr)
			m_DatagramDestination = new i2p::datagram::DatagramDestination (GetSharedFromThis (), gzip);
		return m_DatagramDestination;
	}

	std::vector<std::shared_ptr<const i2p::stream::Stream> > ClientDestination::GetAllStreams () const
	{
		std::vector<std::shared_ptr<const i2p::stream::Stream> > ret;
		if (m_StreamingDestination)
		{
			for (auto& it: m_StreamingDestination->GetStreams ())
				ret.push_back (it.second);
		}
		for (auto& it: m_StreamingDestinationsByPorts)
			for (auto& it1: it.second->GetStreams ())
				ret.push_back (it1.second);
		return ret;
	}

	void ClientDestination::PersistTemporaryKeys (EncryptionKey * keys, bool isSingleKey)
	{
		if (!keys) return;
		std::string ident = GetIdentHash().ToBase32();
		std::string path  = i2p::fs::DataDirPath("destinations",
			isSingleKey ? (ident + ".dat") : (ident + "." + std::to_string (keys->keyType) + ".dat"));
		std::ifstream f(path, std::ifstream::binary);

		if (f) {
			f.read ((char *)keys->pub, 256);
			f.read ((char *)keys->priv, 256);
			return;
		}

		LogPrint (eLogInfo, "Destination: Creating new temporary keys of type for address ", ident, ".b32.i2p");
		memset (keys->priv, 0, 256);
		memset (keys->pub, 0, 256);
		keys->GenerateKeys ();
		// TODO:: persist crypto key type
		std::ofstream f1 (path, std::ofstream::binary | std::ofstream::out);
		if (f1) {
			f1.write ((char *)keys->pub, 256);
			f1.write ((char *)keys->priv, 256);
			return;
		}
		LogPrint(eLogError, "Destinations: Can't save keys to ", path);
	}

	void ClientDestination::CreateNewLeaseSet (std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels)
	{
		std::shared_ptr<i2p::data::LocalLeaseSet> leaseSet;
		if (GetLeaseSetType () == i2p::data::NETDB_STORE_TYPE_LEASESET)
		{
			if (m_StandardEncryptionKey)
			{
				leaseSet = std::make_shared<i2p::data::LocalLeaseSet> (GetIdentity (), m_StandardEncryptionKey->pub, tunnels);
				// sign
				Sign (leaseSet->GetBuffer (), leaseSet->GetBufferLen () - leaseSet->GetSignatureLen (), leaseSet->GetSignature ());
			}
			else
				LogPrint (eLogError, "Destinations: Wrong encryption key type for LeaseSet type 1");
		}
		else
		{
			// standard LS2 (type 3) first
			i2p::data::LocalLeaseSet2::KeySections keySections;
			if (m_ECIESx25519EncryptionKey)
				keySections.push_back ({m_ECIESx25519EncryptionKey->keyType, 32, m_ECIESx25519EncryptionKey->pub} );
			if (m_StandardEncryptionKey)
				keySections.push_back ({m_StandardEncryptionKey->keyType, (uint16_t)m_StandardEncryptionKey->decryptor->GetPublicKeyLen (), m_StandardEncryptionKey->pub} );

			bool isPublishedEncrypted = GetLeaseSetType () == i2p::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2;
			auto ls2 = std::make_shared<i2p::data::LocalLeaseSet2> (i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2,
				m_Keys, keySections, tunnels, IsPublic (), isPublishedEncrypted);
			if (isPublishedEncrypted) // encrypt if type 5
				ls2 = std::make_shared<i2p::data::LocalEncryptedLeaseSet2> (ls2, m_Keys, GetAuthType (), m_AuthKeys);
			leaseSet = ls2;
		}
		SetLeaseSet (leaseSet);
	}

	void ClientDestination::CleanupDestination ()
	{
		if (m_DatagramDestination) m_DatagramDestination->CleanUp ();
	}

	bool ClientDestination::Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, i2p::data::CryptoKeyType preferredCrypto) const
	{
		if (preferredCrypto == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET)
			if (m_ECIESx25519EncryptionKey && m_ECIESx25519EncryptionKey->decryptor)
				return m_ECIESx25519EncryptionKey->decryptor->Decrypt (encrypted, data, ctx, true);
		if (m_StandardEncryptionKey && m_StandardEncryptionKey->decryptor)
			return m_StandardEncryptionKey->decryptor->Decrypt (encrypted, data, ctx, true);
		else
			LogPrint (eLogError, "Destinations: decryptor is not set");
		return false;
	}

	bool ClientDestination::SupportsEncryptionType (i2p::data::CryptoKeyType keyType) const
	{
		return keyType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET ? (bool)m_ECIESx25519EncryptionKey : (bool)m_StandardEncryptionKey;
	}

	const uint8_t * ClientDestination::GetEncryptionPublicKey (i2p::data::CryptoKeyType keyType) const
	{
		if (keyType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET)
			return m_ECIESx25519EncryptionKey ? m_ECIESx25519EncryptionKey->pub : nullptr;
		return m_StandardEncryptionKey ? m_StandardEncryptionKey->pub : nullptr;
	}

	void ClientDestination::ReadAuthKey (const std::string& group, const std::map<std::string, std::string> * params)
	{
		for (auto it: *params)
		if (it.first.length () >= group.length () && !it.first.compare (0, group.length (), group))
		{
			auto pos = it.second.find (':');
			if (pos != std::string::npos)
			{
				i2p::data::AuthPublicKey pubKey;
				if (pubKey.FromBase64 (it.second.substr (pos+1)))
					m_AuthKeys->push_back (pubKey);
				else
					LogPrint (eLogError, "Destination: Unexpected auth key ", it.second.substr (pos+1));
			}
		}
	}

	bool ClientDestination::DeleteStream (uint32_t recvStreamID)
	{
		if (m_StreamingDestination->DeleteStream (recvStreamID))
			return true;
		for (auto it: m_StreamingDestinationsByPorts)
			if (it.second->DeleteStream (recvStreamID))
				return true;
		return false;
	}

	RunnableClientDestination::RunnableClientDestination (const i2p::data::PrivateKeys& keys, bool isPublic, const std::map<std::string, std::string> * params):
		RunnableService ("Destination"),
		ClientDestination (GetIOService (), keys, isPublic, params)
	{
	}

	RunnableClientDestination::~RunnableClientDestination ()
	{
		if (IsRunning ())
			Stop ();
	}

	void RunnableClientDestination::Start ()
	{
		if (!IsRunning ())
		{
			ClientDestination::Start ();
			StartIOService ();
		}
	}

	void RunnableClientDestination::Stop ()
	{
		if (IsRunning ())
		{
			ClientDestination::Stop ();
			StopIOService ();
		}
	}

}
}
