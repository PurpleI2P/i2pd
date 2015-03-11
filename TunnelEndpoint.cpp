#include "I2PEndian.h"
#include <string.h>
#include "Log.h"
#include "NetDb.h"
#include "I2NPProtocol.h"
#include "Transports.h"
#include "RouterContext.h"
#include "TunnelEndpoint.h"

namespace i2p
{
namespace tunnel
{
	TunnelEndpoint::~TunnelEndpoint ()
	{
		for (auto it: m_IncompleteMessages)
			i2p::DeleteI2NPMessage (it.second.data);
		for (auto it: m_OutOfSequenceFragments)
			i2p::DeleteI2NPMessage (it.second.data);
	}	
	
	void TunnelEndpoint::HandleDecryptedTunnelDataMsg (I2NPMessage * msg)
	{
		m_NumReceivedBytes += TUNNEL_DATA_MSG_SIZE;
		
		uint8_t * decrypted = msg->GetPayload () + 20; // 4 + 16
		uint8_t * zero = (uint8_t *)memchr (decrypted + 4, 0, TUNNEL_DATA_ENCRYPTED_SIZE - 4); // witout 4-byte checksum
		if (zero)
		{	
			uint8_t * fragment = zero + 1;
			// verify checksum
			memcpy (msg->GetPayload () + TUNNEL_DATA_MSG_SIZE, msg->GetPayload () + 4, 16); // copy iv to the end
			uint8_t hash[32];
			CryptoPP::SHA256().CalculateDigest (hash, fragment, TUNNEL_DATA_MSG_SIZE -(fragment - msg->GetPayload ()) + 16); // payload + iv
			if (memcmp (hash, decrypted, 4))
			{
				LogPrint (eLogError, "TunnelMessage: checksum verification failed");
				i2p::DeleteI2NPMessage (msg);
				return;
			}	
			// process fragments
			while (fragment < decrypted + TUNNEL_DATA_ENCRYPTED_SIZE)
			{
				uint8_t flag = fragment[0];
				fragment++;
				
				bool isFollowOnFragment = flag & 0x80, isLastFragment = true;		
				uint32_t msgID = 0;
				int fragmentNum = 0;
				TunnelMessageBlockEx m;
				if (!isFollowOnFragment)
				{	
					// first fragment
					
					m.deliveryType = (TunnelDeliveryType)((flag >> 5) & 0x03);
					switch (m.deliveryType)
					{
						case eDeliveryTypeLocal: // 0
						break;
					  	case eDeliveryTypeTunnel: // 1
							m.tunnelID = bufbe32toh (fragment);
							fragment += 4; // tunnelID
							m.hash = i2p::data::IdentHash (fragment);
							fragment += 32; // hash
						break;
						case eDeliveryTypeRouter: // 2
							m.hash = i2p::data::IdentHash (fragment);	
							fragment += 32; // to hash
						break;
						default:
							;
					}	

					bool isFragmented = flag & 0x08;
					if (isFragmented)
					{
						// Message ID
						msgID = bufbe32toh (fragment); 	
						fragment += 4;
						isLastFragment = false;
					}	
				}
				else
				{
					// follow on
					msgID = bufbe32toh (fragment); // MessageID			
					fragment += 4; 
					fragmentNum = (flag >> 1) & 0x3F; // 6 bits
					isLastFragment = flag & 0x01;
				}	
				
				uint16_t size = bufbe16toh (fragment);
				fragment += 2;

				msg->offset = fragment - msg->buf;
				msg->len = msg->offset + size;
				if (fragment + size < decrypted + TUNNEL_DATA_ENCRYPTED_SIZE)
				{
					// this is not last message. we have to copy it
					m.data = NewI2NPShortMessage ();
					m.data->offset += TUNNEL_GATEWAY_HEADER_SIZE; // reserve room for TunnelGateway header
					m.data->len += TUNNEL_GATEWAY_HEADER_SIZE;
					*(m.data) = *msg;
				}
				else
					m.data = msg;
				
				if (!isFollowOnFragment && isLastFragment)
					HandleNextMessage (m);
				else
				{
					if (msgID) // msgID is presented, assume message is fragmented
					{
						if (!isFollowOnFragment) // create new incomlete message
						{
							m.nextFragmentNum = 1;
							auto ret = m_IncompleteMessages.insert (std::pair<uint32_t, TunnelMessageBlockEx>(msgID, m));
							if (ret.second)
								HandleOutOfSequenceFragment (msgID, ret.first->second);
							else
							{
								LogPrint (eLogError, "Incomplete message ", msgID, "already exists");
								DeleteI2NPMessage (m.data);
							}	
						}
						else
						{
							m.nextFragmentNum = fragmentNum;
							HandleFollowOnFragment (msgID, isLastFragment, m);
						}	
					}
					else	
					{	
						LogPrint (eLogError, "Message is fragmented, but msgID is not presented");
						DeleteI2NPMessage (m.data);
					}	
				}	
					
				fragment += size;
			}	
		}	
		else
		{	
			LogPrint (eLogError, "TunnelMessage: zero not found");
			i2p::DeleteI2NPMessage (msg);	
		}	
	}	

	void TunnelEndpoint::HandleFollowOnFragment (uint32_t msgID, bool isLastFragment, const TunnelMessageBlockEx& m)
	{
		auto fragment = m.data->GetBuffer ();
		auto size = m.data->GetLength ();
		auto it = m_IncompleteMessages.find (msgID);
		if (it != m_IncompleteMessages.end())
		{
			auto& msg = it->second;
			if (m.nextFragmentNum == msg.nextFragmentNum)
			{
				if (msg.data->len + size < I2NP_MAX_MESSAGE_SIZE) // check if message is not too long
				{	
					if (msg.data->len + size > msg.data->maxLen)
					{
						LogPrint (eLogInfo, "Tunnel endpoint I2NP message size ", msg.data->maxLen, " is not enough");
						I2NPMessage * newMsg = NewI2NPMessage ();
						*newMsg = *(msg.data);
						DeleteI2NPMessage (msg.data);
						msg.data = newMsg;
					}
					memcpy (msg.data->buf + msg.data->len, fragment, size); // concatenate fragment
					msg.data->len += size;
					if (isLastFragment)
					{
						// message complete
						HandleNextMessage (msg);	
						m_IncompleteMessages.erase (it); 
					}	
					else
					{	
						msg.nextFragmentNum++;
						HandleOutOfSequenceFragment (msgID, msg);
					}	
				}
				else
				{
					LogPrint (eLogError, "Fragment ", m.nextFragmentNum, " of message ", msgID, "exceeds max I2NP message size. Message dropped");
					i2p::DeleteI2NPMessage (msg.data);
					m_IncompleteMessages.erase (it);
				}
				i2p::DeleteI2NPMessage (m.data);
			}
			else
			{	
				LogPrint (eLogInfo, "Unexpected fragment ", (int)m.nextFragmentNum, " instead ", (int)msg.nextFragmentNum, " of message ", msgID, ". Saved");
				AddOutOfSequenceFragment (msgID, m.nextFragmentNum, isLastFragment, m.data);
			}
		}
		else
		{	
			LogPrint (eLogInfo, "First fragment of message ", msgID, " not found. Saved");
			AddOutOfSequenceFragment (msgID, m.nextFragmentNum, isLastFragment, m.data);
		}	
	}	

	void TunnelEndpoint::AddOutOfSequenceFragment (uint32_t msgID, uint8_t fragmentNum, bool isLastFragment, I2NPMessage * data)
	{
		auto it = m_OutOfSequenceFragments.find (msgID);
		if (it == m_OutOfSequenceFragments.end ())
			m_OutOfSequenceFragments.insert (std::pair<uint32_t, Fragment> (msgID, {fragmentNum, isLastFragment, data}));	
		else
			i2p::DeleteI2NPMessage (data);
	}	

	void TunnelEndpoint::HandleOutOfSequenceFragment (uint32_t msgID, TunnelMessageBlockEx& msg)
	{
		auto it = m_OutOfSequenceFragments.find (msgID);
		if (it != m_OutOfSequenceFragments.end ())
		{
			if (it->second.fragmentNum == msg.nextFragmentNum)
			{
				LogPrint (eLogInfo, "Out-of-sequence fragment ", (int)it->second.fragmentNum, " of message ", msgID, " found");
				auto size = it->second.data->GetLength ();
				if (msg.data->len + size > msg.data->maxLen)
				{
					LogPrint (eLogInfo, "Tunnel endpoint I2NP message size ", msg.data->maxLen, " is not enough");
					I2NPMessage * newMsg = NewI2NPMessage ();
					*newMsg = *(msg.data);
					DeleteI2NPMessage (msg.data);
					msg.data = newMsg;
				}
				memcpy (msg.data->buf + msg.data->len, it->second.data->GetBuffer (), size); // concatenate out-of-sync fragment
				msg.data->len += size;
				if (it->second.isLastFragment)
				{
					// message complete
					HandleNextMessage (msg);	
					m_IncompleteMessages.erase (msgID); 
				}	
				else
					msg.nextFragmentNum++;
				i2p::DeleteI2NPMessage (it->second.data);
				m_OutOfSequenceFragments.erase (it);
			}	
		}	
	}	
	
	void TunnelEndpoint::HandleNextMessage (const TunnelMessageBlock& msg)
	{
		LogPrint (eLogInfo, "TunnelMessage: handle fragment of ", msg.data->GetLength ()," bytes. Msg type ", (int)msg.data->GetTypeID ());
		switch (msg.deliveryType)
		{
			case eDeliveryTypeLocal:
				i2p::HandleI2NPMessage (msg.data);
			break;
			case eDeliveryTypeTunnel:
				i2p::transport::transports.SendMessage (msg.hash, i2p::CreateTunnelGatewayMsg (msg.tunnelID, msg.data));
			break;
			case eDeliveryTypeRouter:
				if (msg.hash == i2p::context.GetRouterInfo ().GetIdentHash ()) // check if message is sent to us
					i2p::HandleI2NPMessage (msg.data);
				else
				{	
					// to somebody else
					if (!m_IsInbound) // outbound transit tunnel
					{
						auto typeID = msg.data->GetTypeID ();
						if (typeID == eI2NPDatabaseStore || typeID == eI2NPDatabaseSearchReply )
						{
							// catch RI or reply with new list of routers
							auto ds = NewI2NPShortMessage ();
							*ds = *(msg.data);
							i2p::data::netdb.PostI2NPMsg (ds);
						}
						i2p::transport::transports.SendMessage (msg.hash, msg.data);
					}
					else // we shouldn't send this message. possible leakage 
					{
						LogPrint (eLogError, "Message to another router arrived from an inbound tunnel. Dropped");
						i2p::DeleteI2NPMessage (msg.data);
					}
				}
			break;
			default:
			{	
				LogPrint (eLogError, "TunnelMessage: Unknown delivery type ", (int)msg.deliveryType);
				i2p::DeleteI2NPMessage (msg.data);
			}	
		};	
	}	
}		
}
