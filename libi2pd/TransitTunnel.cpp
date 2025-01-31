/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "I2PEndian.h"
#include "Crypto.h"
#include "Log.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "Garlic.h"
#include "ECIESX25519AEADRatchetSession.h"
#include "Tunnel.h"
#include "Transports.h"
#include "TransitTunnel.h"

namespace i2p
{
namespace tunnel
{
	TransitTunnel::TransitTunnel (uint32_t receiveTunnelID,
		const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
		const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey):
			TunnelBase (receiveTunnelID, nextTunnelID, nextIdent),
			m_LayerKey (layerKey), m_IVKey (ivKey)
	{
	}

	void TransitTunnel::EncryptTunnelMsg (std::shared_ptr<const I2NPMessage> in, std::shared_ptr<I2NPMessage> out)
	{
		if (!m_Encryption)
		{
			m_Encryption.reset (new i2p::crypto::TunnelEncryption);
			m_Encryption->SetKeys (m_LayerKey, m_IVKey);
		}
		m_Encryption->Encrypt (in->GetPayload () + 4, out->GetPayload () + 4);
		i2p::transport::transports.UpdateTotalTransitTransmittedBytes (TUNNEL_DATA_MSG_SIZE);
	}

	std::string TransitTunnel::GetNextPeerName () const
	{
		return i2p::data::GetIdentHashAbbreviation (GetNextIdentHash ());
	}	

	void TransitTunnel::SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg)
	{
		LogPrint (eLogError, "TransitTunnel: We are not a gateway for ", GetTunnelID ());
	}

	void TransitTunnel::HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg)
	{
		LogPrint (eLogError, "TransitTunnel: Incoming tunnel message is not supported ", GetTunnelID ());
	}
		
	TransitTunnelParticipant::~TransitTunnelParticipant ()
	{
	}

	void TransitTunnelParticipant::HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg)
	{
		EncryptTunnelMsg (tunnelMsg, tunnelMsg);

		m_NumTransmittedBytes += tunnelMsg->GetLength ();
		htobe32buf (tunnelMsg->GetPayload (), GetNextTunnelID ());
		tunnelMsg->FillI2NPMessageHeader (eI2NPTunnelData);
		m_TunnelDataMsgs.push_back (tunnelMsg);
	}

	void TransitTunnelParticipant::FlushTunnelDataMsgs ()
	{
		if (!m_TunnelDataMsgs.empty ())
		{
			auto num = m_TunnelDataMsgs.size ();
			if (num > 1)
				LogPrint (eLogDebug, "TransitTunnel: ", GetTunnelID (), "->", GetNextTunnelID (), " ", num);
			if (!m_Sender) m_Sender = std::make_unique<TunnelTransportSender>();
			m_Sender->SendMessagesTo (GetNextIdentHash (), m_TunnelDataMsgs); // send and clear
		}
	}

	std::string TransitTunnelParticipant::GetNextPeerName () const
	{
		if (m_Sender)
		{
			auto transport = m_Sender->GetCurrentTransport ();
			if (transport)
				return TransitTunnel::GetNextPeerName () + "-" + 
					i2p::data::RouterInfo::GetTransportName (transport->GetTransportType ());
		}	
		return TransitTunnel::GetNextPeerName ();
	}	
		
	void TransitTunnelGateway::SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg)
	{
		TunnelMessageBlock block;
		block.deliveryType = eDeliveryTypeLocal;
		block.data = msg;
		std::lock_guard<std::mutex> l(m_SendMutex);
		m_Gateway.PutTunnelDataMsg (block);
	}

	void TransitTunnelGateway::FlushTunnelDataMsgs ()
	{
		std::lock_guard<std::mutex> l(m_SendMutex);
		m_Gateway.SendBuffer ();
	}

	std::string TransitTunnelGateway::GetNextPeerName () const
	{
		const auto& sender = m_Gateway.GetSender ();
		if (sender)
		{
			auto transport = sender->GetCurrentTransport ();
			if (transport)
				return TransitTunnel::GetNextPeerName () + "-" + 
					i2p::data::RouterInfo::GetTransportName (transport->GetTransportType ());
		}	
		return TransitTunnel::GetNextPeerName ();
	}	
		
	void TransitTunnelEndpoint::HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg)
	{
		auto newMsg = CreateEmptyTunnelDataMsg (true);
		EncryptTunnelMsg (tunnelMsg, newMsg);

		LogPrint (eLogDebug, "TransitTunnel: handle msg for endpoint ", GetTunnelID ());
		std::lock_guard<std::mutex> l(m_HandleMutex);
		m_Endpoint.HandleDecryptedTunnelDataMsg (newMsg);
	}

	void TransitTunnelEndpoint::FlushTunnelDataMsgs ()
	{
		std::lock_guard<std::mutex> l(m_HandleMutex);
		m_Endpoint.FlushI2NPMsgs ();
	}	

	void TransitTunnelEndpoint::Cleanup ()
	{ 
		std::lock_guard<std::mutex> l(m_HandleMutex);
		m_Endpoint.Cleanup ();
	}	
		
	std::string TransitTunnelEndpoint::GetNextPeerName () const
	{ 
		auto hash = m_Endpoint.GetCurrentHash ();
		if (hash)
		{	
			const auto& sender = m_Endpoint.GetSender ();
			if (sender)
			{
				auto transport = sender->GetCurrentTransport ();
				if (transport)
					return i2p::data::GetIdentHashAbbreviation (*hash) + "-" + 
						i2p::data::RouterInfo::GetTransportName (transport->GetTransportType ());
				else
					return i2p::data::GetIdentHashAbbreviation (*hash);
			}	
		}
		return "";
	}	
		
	std::shared_ptr<TransitTunnel> CreateTransitTunnel (uint32_t receiveTunnelID,
		const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
		const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey,
		bool isGateway, bool isEndpoint)
	{
		if (isEndpoint)
		{
			LogPrint (eLogDebug, "TransitTunnel: endpoint ", receiveTunnelID, " created");
			return std::make_shared<TransitTunnelEndpoint> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}
		else if (isGateway)
		{
			LogPrint (eLogInfo, "TransitTunnel: gateway ", receiveTunnelID, " created");
			return std::make_shared<TransitTunnelGateway> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}
		else
		{
			LogPrint (eLogDebug, "TransitTunnel: ", receiveTunnelID, "->", nextTunnelID, " created");
			return std::make_shared<TransitTunnelParticipant> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}
	}

	TransitTunnels::TransitTunnels ():
		m_IsRunning (false), m_Rng(i2p::util::GetMonotonicMicroseconds ()%1000000LL)
	{
	}
		
	TransitTunnels::~TransitTunnels ()
	{
		Stop ();
	}	
		
	void TransitTunnels::Start () 
	{
		m_IsRunning = true;
		m_Thread.reset (new std::thread (std::bind (&TransitTunnels::Run, this)));
	}
		
	void TransitTunnels::Stop ()
	{
		m_IsRunning = false;
		m_TunnelBuildMsgQueue.WakeUp ();
		if (m_Thread)
		{
			m_Thread->join ();
			m_Thread = nullptr;
		}
		m_TransitTunnels.clear ();
	}	

	void TransitTunnels::Run () 
	{
		i2p::util::SetThreadName("TBM");
		uint64_t lastTs = 0;
		std::list<std::shared_ptr<I2NPMessage> > msgs;
		while (m_IsRunning)
		{
			try
			{
				if (m_TunnelBuildMsgQueue.Wait (TRANSIT_TUNNELS_QUEUE_WAIT_INTERVAL, 0))
				{
					m_TunnelBuildMsgQueue.GetWholeQueue (msgs);
					while (!msgs.empty ())
					{
						auto msg = msgs.front (); msgs.pop_front ();
						if (!msg) continue;
						uint8_t typeID = msg->GetTypeID ();
						switch (typeID)
						{
							case eI2NPShortTunnelBuild:
								HandleShortTransitTunnelBuildMsg (std::move (msg));
							break;	
							case eI2NPVariableTunnelBuild:
								HandleVariableTransitTunnelBuildMsg (std::move (msg));
							break;	
							default:
								LogPrint (eLogWarning, "TransitTunnel: Unexpected message type ", (int) typeID);
						}
						if (!m_IsRunning) break;
					}	
				}	
				if (m_IsRunning)
				{
					uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
					if (ts  >= lastTs + TUNNEL_MANAGE_INTERVAL || ts + TUNNEL_MANAGE_INTERVAL < lastTs)
					{
						ManageTransitTunnels (ts);
						lastTs = ts;
					}
				}	
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "TransitTunnel: Runtime exception: ", ex.what ());
			}
		}
	}

	void TransitTunnels::PostTransitTunnelBuildMsg  (std::shared_ptr<I2NPMessage>&& msg)
	{
		if (msg) m_TunnelBuildMsgQueue.Put (msg);
	}	
		
	void TransitTunnels::HandleShortTransitTunnelBuildMsg (std::shared_ptr<I2NPMessage>&& msg)
	{
		if (!msg) return;
		uint8_t * buf = msg->GetPayload();
		size_t len = msg->GetPayloadLength();
		int num = buf[0];
		LogPrint (eLogDebug, "TransitTunnel: ShortTunnelBuild ", num, " records");
		if (num > i2p::tunnel::MAX_NUM_RECORDS)
		{
			LogPrint (eLogError, "TransitTunnel: Too many records in ShortTunnelBuild message ", num);
			return;
		}
		if (len < num*SHORT_TUNNEL_BUILD_RECORD_SIZE + 1)
		{
			LogPrint (eLogError, "TransitTunnel: ShortTunnelBuild message of ", num, " records is too short ", len);
			return;
		}
		const uint8_t * record = buf + 1;
		for (int i = 0; i < num; i++)
		{
			if (!memcmp (record, (const uint8_t *)i2p::context.GetRouterInfo ().GetIdentHash (), 16))
			{
				LogPrint (eLogDebug, "TransitTunnel: Short request record ", i, " is ours");
				uint8_t clearText[SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE];
				if (!i2p::context.DecryptTunnelShortRequestRecord (record + SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET, clearText))
				{
					LogPrint (eLogWarning, "TransitTunnel: Can't decrypt short request record ", i);
					return;
				}
				if (clearText[SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE]) // not AES
				{
					LogPrint (eLogWarning, "TransitTunnel: Unknown layer encryption type ", clearText[SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE], " in short request record");
					return;
				}
				auto& noiseState = i2p::context.GetCurrentNoiseState ();
				uint8_t replyKey[32]; // AEAD/Chacha20/Poly1305
				i2p::crypto::AESKey layerKey, ivKey; // AES
				i2p::crypto::HKDF (noiseState.m_CK, nullptr, 0, "SMTunnelReplyKey", noiseState.m_CK);
				memcpy (replyKey, noiseState.m_CK + 32, 32);
				i2p::crypto::HKDF (noiseState.m_CK, nullptr, 0, "SMTunnelLayerKey", noiseState.m_CK);
				memcpy (layerKey, noiseState.m_CK + 32, 32);
				bool isEndpoint = clearText[SHORT_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG;
				if (isEndpoint)
				{
					i2p::crypto::HKDF (noiseState.m_CK, nullptr, 0, "TunnelLayerIVKey", noiseState.m_CK);
					memcpy (ivKey, noiseState.m_CK + 32, 32);
				}
				else
				{	
					if (!memcmp ((const uint8_t *)i2p::context.GetIdentHash (), clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET, 32)) // if next ident is now ours
					{
						LogPrint (eLogWarning, "TransitTunnel: Next ident is ours in short request record");
						return;
					}	
					memcpy (ivKey, noiseState.m_CK , 32);
				}	

				// check if we accept this tunnel
				std::shared_ptr<i2p::tunnel::TransitTunnel> transitTunnel;
				uint8_t retCode = 0;
				if (i2p::context.AcceptsTunnels ())
				{
					auto congestionLevel = i2p::context.GetCongestionLevel (false);
					if (congestionLevel < CONGESTION_LEVEL_FULL)
					{	
						if (congestionLevel >= CONGESTION_LEVEL_MEDIUM)
						{	
							// random reject depending on congestion level
							int level = m_Rng () % (CONGESTION_LEVEL_FULL - CONGESTION_LEVEL_MEDIUM) + CONGESTION_LEVEL_MEDIUM;
							if (congestionLevel > level)
								retCode = 30;
						}	
					}	
					else
						retCode = 30;
				}	
				else	
					retCode = 30;
				
				if (!retCode)
				{
					i2p::data::IdentHash nextIdent(clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET);
					bool isEndpoint = clearText[SHORT_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG;
					if (isEndpoint || !i2p::data::IsRouterDuplicated (nextIdent))
					{	
						// create new transit tunnel
						transitTunnel = CreateTransitTunnel (
							bufbe32toh (clearText + SHORT_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET),
							nextIdent,
							bufbe32toh (clearText + SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
							layerKey, ivKey,
							clearText[SHORT_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_GATEWAY_FLAG,
							isEndpoint);
						if (!AddTransitTunnel (transitTunnel))
							retCode = 30;
					}
					else
						// decline tunnel going to duplicated router 
						retCode = 30;
				}

				// encrypt reply
				uint8_t nonce[12];
				memset (nonce, 0, 12);
				uint8_t * reply = buf + 1;
				for (int j = 0; j < num; j++)
				{
					nonce[4] = j; // nonce is record #
					if (j == i)
					{
						memset (reply + SHORT_RESPONSE_RECORD_OPTIONS_OFFSET, 0, 2); // no options
						reply[SHORT_RESPONSE_RECORD_RET_OFFSET] = retCode;
						if (!i2p::crypto::AEADChaCha20Poly1305 (reply, SHORT_TUNNEL_BUILD_RECORD_SIZE - 16,
							noiseState.m_H, 32, replyKey, nonce, reply, SHORT_TUNNEL_BUILD_RECORD_SIZE, true)) // encrypt
						{
							LogPrint (eLogWarning, "TransitTunnel: Short reply AEAD encryption failed");
							return;
						}
					}
					else
						i2p::crypto::ChaCha20 (reply, SHORT_TUNNEL_BUILD_RECORD_SIZE, replyKey, nonce, reply);
					reply += SHORT_TUNNEL_BUILD_RECORD_SIZE;
				}
				// send reply
				auto onDrop = [transitTunnel]()
					{
						if (transitTunnel)
						{
							LogPrint (eLogDebug, "TransitTunnel: Failed to send reply for transit tunnel ", transitTunnel->GetTunnelID ());
							auto t = transitTunnel->GetCreationTime ();
							if (t > i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT)
								// make transit tunnel expired 
								transitTunnel->SetCreationTime (t - i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT);
						}	
					};
				if (isEndpoint)
				{
					auto replyMsg = NewI2NPShortMessage ();
					replyMsg->Concat (buf, len);
					replyMsg->FillI2NPMessageHeader (eI2NPShortTunnelBuildReply, bufbe32toh (clearText + SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET));
					if (transitTunnel) replyMsg->onDrop = onDrop;
					if (memcmp ((const uint8_t *)i2p::context.GetIdentHash (),
						clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET, 32)) // reply IBGW is not local?
					{
						i2p::crypto::HKDF (noiseState.m_CK, nullptr, 0, "RGarlicKeyAndTag", noiseState.m_CK);
						uint64_t tag;
						memcpy (&tag, noiseState.m_CK, 8);
						// we send it to reply tunnel
						i2p::transport::transports.SendMessage (clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET,
						CreateTunnelGatewayMsg (bufbe32toh (clearText + SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
							i2p::garlic::WrapECIESX25519Message (replyMsg, noiseState.m_CK + 32, tag)));
					}
					else
					{
						// IBGW is local
						uint32_t tunnelID = bufbe32toh (clearText + SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET);
						auto tunnel = i2p::tunnel::tunnels.GetTunnel (tunnelID);
						if (tunnel)
						{	
							tunnel->SendTunnelDataMsg (replyMsg);
							tunnel->FlushTunnelDataMsgs ();
						}	
						else
							LogPrint (eLogWarning, "I2NP: Tunnel ", tunnelID, " not found for short tunnel build reply");
					}
				}
				else
				{
					auto msg = CreateI2NPMessage (eI2NPShortTunnelBuild, buf, len,
							bufbe32toh (clearText + SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET));
					if (transitTunnel) msg->onDrop = onDrop;
					i2p::transport::transports.SendMessage (clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET, msg);
				}	
				return;
			}
			record += SHORT_TUNNEL_BUILD_RECORD_SIZE;
		}
	}	
		
	bool TransitTunnels::HandleBuildRequestRecords (int num, uint8_t * records, uint8_t * clearText)
	{
		for (int i = 0; i < num; i++)
		{
			uint8_t * record = records + i*TUNNEL_BUILD_RECORD_SIZE;
			if (!memcmp (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)i2p::context.GetRouterInfo ().GetIdentHash (), 16))
			{
				LogPrint (eLogDebug, "TransitTunnel: Build request record ", i, " is ours");
				if (!i2p::context.DecryptTunnelBuildRecord (record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET, clearText)) 
				{
					LogPrint (eLogWarning, "TransitTunnel: Failed to decrypt tunnel build record");
					return false;
				}	
				if (!memcmp ((const uint8_t *)i2p::context.GetIdentHash (), clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET, 32) && // if next ident is now ours
				    !(clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG)) // and not endpoint
				{
					LogPrint (eLogWarning, "TransitTunnel: Next ident is ours in tunnel build record");
					return false;
				}	
				uint8_t retCode = 0;
				// decide if we should accept tunnel
				bool accept = i2p::context.AcceptsTunnels ();
				if (accept)
				{
					auto congestionLevel = i2p::context.GetCongestionLevel (false);
					if (congestionLevel >= CONGESTION_LEVEL_MEDIUM)
					{	
						if (congestionLevel < CONGESTION_LEVEL_FULL)
						{
							// random reject depending on congestion level
							int level = m_Rng () % (CONGESTION_LEVEL_FULL - CONGESTION_LEVEL_MEDIUM) + CONGESTION_LEVEL_MEDIUM;
							if (congestionLevel > level)
								accept = false;
						}	
						else	
							accept = false;
					}	
				}	
					
				if (accept)
				{
					i2p::data::IdentHash nextIdent(clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET);
					bool isEndpoint = clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG;
					if (isEndpoint || !i2p::data::IsRouterDuplicated (nextIdent))
					{	
						auto transitTunnel = CreateTransitTunnel (
								bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET),
								nextIdent,
								bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
								clearText + ECIES_BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET,
								clearText + ECIES_BUILD_REQUEST_RECORD_IV_KEY_OFFSET,
								clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_GATEWAY_FLAG,
								isEndpoint);
						if (!AddTransitTunnel (transitTunnel))
							retCode = 30;
					}	
					else
						// decline tunnel going to duplicated router 
						retCode = 30;
				}
				else
					retCode = 30; // always reject with bandwidth reason (30)

				// replace record to reply
				memset (record + ECIES_BUILD_RESPONSE_RECORD_OPTIONS_OFFSET, 0, 2); // no options
				record[ECIES_BUILD_RESPONSE_RECORD_RET_OFFSET] = retCode;
				// encrypt reply
				i2p::crypto::CBCEncryption encryption;
				for (int j = 0; j < num; j++)
				{
					uint8_t * reply = records + j*TUNNEL_BUILD_RECORD_SIZE;
					if (j == i)
					{
						uint8_t nonce[12];
						memset (nonce, 0, 12);
						auto& noiseState = i2p::context.GetCurrentNoiseState ();
						if (!i2p::crypto::AEADChaCha20Poly1305 (reply, TUNNEL_BUILD_RECORD_SIZE - 16,
							noiseState.m_H, 32, noiseState.m_CK, nonce, reply, TUNNEL_BUILD_RECORD_SIZE, true)) // encrypt
						{
							LogPrint (eLogWarning, "TransitTunnel: Reply AEAD encryption failed");
							return false;
						}
					}
					else
					{
						encryption.SetKey (clearText + ECIES_BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET);
						encryption.Encrypt(reply, TUNNEL_BUILD_RECORD_SIZE, clearText + ECIES_BUILD_REQUEST_RECORD_REPLY_IV_OFFSET, reply);
					}
				}
				return true;
			}
		}
		return false;
	}

	void TransitTunnels::HandleVariableTransitTunnelBuildMsg (std::shared_ptr<I2NPMessage>&& msg)
	{
		if (!msg) return;
		uint8_t * buf = msg->GetPayload();
		size_t len = msg->GetPayloadLength();
		int num = buf[0];
		LogPrint (eLogDebug, "TransitTunnel: VariableTunnelBuild ", num, " records");
		if (num > i2p::tunnel::MAX_NUM_RECORDS)
		{
			LogPrint (eLogError, "TransitTunnle: Too many records in VaribleTunnelBuild message ", num);
			return;
		}
		if (len < num*TUNNEL_BUILD_RECORD_SIZE + 1)
		{
			LogPrint (eLogError, "TransitTunnel: VaribleTunnelBuild message of ", num, " records is too short ", len);
			return;
		}
		uint8_t clearText[ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];
		if (HandleBuildRequestRecords (num, buf + 1, clearText))
		{
			if (clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG) // we are endpoint of outboud tunnel
			{
				// so we send it to reply tunnel
				i2p::transport::transports.SendMessage (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
					CreateTunnelGatewayMsg (bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
						eI2NPVariableTunnelBuildReply, buf, len,
						bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET)));
			}
			else
				i2p::transport::transports.SendMessage (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
					CreateI2NPMessage (eI2NPVariableTunnelBuild, buf, len,
						bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET)));
		}
	}

	bool TransitTunnels::AddTransitTunnel (std::shared_ptr<TransitTunnel> tunnel)
	{
		if (tunnels.AddTunnel (tunnel))
			m_TransitTunnels.push_back (tunnel);
		else
		{
			LogPrint (eLogError, "TransitTunnel: Tunnel with id ", tunnel->GetTunnelID (), " already exists");
			return false;
		}
		return true;
	}
		
	void TransitTunnels::ManageTransitTunnels (uint64_t ts)
	{
		for (auto it = m_TransitTunnels.begin (); it != m_TransitTunnels.end ();)
		{
			auto tunnel = *it;
			if (ts > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT ||
			    ts + TUNNEL_EXPIRATION_TIMEOUT < tunnel->GetCreationTime ())
			{
				LogPrint (eLogDebug, "TransitTunnel: Transit tunnel with id ", tunnel->GetTunnelID (), " expired");
				tunnels.RemoveTunnel (tunnel->GetTunnelID ());
				it = m_TransitTunnels.erase (it);
			}
			else
			{
				tunnel->Cleanup ();
				it++;
			}
		}
	}

	int TransitTunnels::GetTransitTunnelsExpirationTimeout ()
	{
		int timeout = 0;
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		// TODO: possible race condition with I2PControl
		for (const auto& it : m_TransitTunnels)
		{
			int t = it->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT - ts;
			if (t > timeout) timeout = t;
		}
		return timeout;
	}	
}
}
