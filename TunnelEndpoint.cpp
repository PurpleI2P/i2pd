#include <endian.h>
#include <string.h>
#include "Log.h"
#include "I2NPProtocol.h"
#include "Transports.h"
#include "TunnelEndpoint.h"

namespace i2p
{
namespace tunnel
{
	void TunnelEndpoint::HandleDecryptedTunnelDataMsg (I2NPMessage * msg)
	{
		m_NumReceivedBytes += TUNNEL_DATA_MSG_SIZE;
		
		uint8_t * decrypted = msg->GetPayload () + 20; // 4 + 16
		uint8_t * zero = (uint8_t *)memchr (decrypted + 4, 0, TUNNEL_DATA_ENCRYPTED_SIZE - 4); // witout 4-byte checksum
		if (zero)
		{	
			LogPrint ("TunnelMessage: zero found at ", (int)(zero-decrypted));
			uint8_t * fragment = zero + 1;
			while (fragment < decrypted + TUNNEL_DATA_ENCRYPTED_SIZE)
			{
				uint8_t flag = fragment[0];
				fragment++;
				
				bool isFollowOnFragment = flag & 0x80, isLastFragment = true;		
				uint32_t msgID = 0;
				TunnelMessageBlock m;
				if (!isFollowOnFragment)
				{	
					// first fragment
					
					m.deliveryType = (TunnelDeliveryType)((flag >> 5) & 0x03);
					switch (m.deliveryType)
					{
						case eDeliveryTypeLocal: // 0
							LogPrint ("Delivery type local");
						break;
					  	case eDeliveryTypeTunnel: // 1
							LogPrint ("Delivery type tunnel");	
							m.tunnelID = be32toh (*(uint32_t *)fragment);
							fragment += 4; // tunnelID
							memcpy (m.hash, fragment, 32);
							fragment += 32; // hash
						break;
						case eDeliveryTypeRouter: // 2
							LogPrint ("Delivery type router");	
							memcpy (m.hash, fragment, 32);	
							fragment += 32; // to hash
						break;
						default:
							;
					}	

					bool isFragmented = flag & 0x08;
					if (isFragmented)
					{
						// Message ID
						msgID = be32toh (*(uint32_t *)fragment); 	
						fragment += 4;
						LogPrint ("Fragmented message ", msgID);
						isLastFragment = false;
					}	
				}
				else
				{
					// follow on
					msgID = be32toh (*(uint32_t *)fragment); // MessageID			
					fragment += 4; 
					int fragmentNum = (flag >> 1) & 0x3F; // 6 bits
					isLastFragment = flag & 0x01;
					LogPrint ("Follow on fragment ", fragmentNum, " of message ", msgID, isLastFragment ? " last" : " non-last");
				}	
				
				uint16_t size = be16toh (*(uint16_t *)fragment);
				fragment += 2;
				LogPrint ("Fragment size=", (int)size);

				msg->offset = fragment - msg->buf;
				msg->len = msg->offset + size;
				bool isLastMessage = false;
				if (fragment + size < decrypted + TUNNEL_DATA_ENCRYPTED_SIZE)
				{
					// this is not last message. we have to copy it
					m.data = NewI2NPMessage ();
					m.data->offset += sizeof (TunnelGatewayHeader); // reserve room for TunnelGateway header
					m.data->len += sizeof (TunnelGatewayHeader);
					*(m.data) = *msg;
				}
				else
				{	
					m.data = msg;
					isLastMessage = true;
				}
				
				if (!isFollowOnFragment && isLastFragment)
					HandleNextMessage (m);
				else
				{
					if (msgID) // msgID is presented, assume message is fragmented
					{
						if (!isFollowOnFragment) // create new incomlete message
							m_IncompleteMessages[msgID] = m;
						else
						{
							auto it = m_IncompleteMessages.find (msgID);
							if (it != m_IncompleteMessages.end())
							{
								I2NPMessage * incompleteMessage = it->second.data; 
								memcpy (incompleteMessage->buf + incompleteMessage->len, fragment, size); // concatenate fragment
								incompleteMessage->len += size;
								// TODO: check fragmentNum sequence
								if (isLastFragment)
								{
									// message complete
									HandleNextMessage (it->second);	
									m_IncompleteMessages.erase (it); 
								}	
							}
							else
								LogPrint ("First fragment of message ", msgID, " not found. Discarded");

							if (isLastMessage) 
								// last message is follow-on fragment
								// not passed to anywhere because first fragment
								i2p::DeleteI2NPMessage (msg);
						}	
					}
					else
						LogPrint ("Message is fragmented, but msgID is not presented");
				}	
					
				fragment += size;
			}	
		}	
		else
		{	
			LogPrint ("TunnelMessage: zero not found");
			i2p::DeleteI2NPMessage (msg);	
		}	
	}	

	void TunnelEndpoint::HandleNextMessage (const TunnelMessageBlock& msg)
	{
		LogPrint ("TunnelMessage: handle fragment of ", msg.data->GetLength ()," bytes");
		switch (msg.deliveryType)
		{
			case eDeliveryTypeLocal:
				i2p::HandleI2NPMessage (msg.data, true);
			break;
			case eDeliveryTypeTunnel:
				i2p::transports.SendMessage (msg.hash, i2p::CreateTunnelGatewayMsg (msg.tunnelID, msg.data));
			break;
			case eDeliveryTypeRouter:
				i2p::transports.SendMessage (msg.hash, msg.data);
			break;
			default:
				LogPrint ("TunnelMessage: Unknown delivery type ", (int)msg.deliveryType);
		};	
	}	
}		
}
