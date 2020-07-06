/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "Crypto.h"
#include "I2PEndian.h"
#include "Log.h"
#include "RouterContext.h"
#include "Transports.h"
#include "TunnelGateway.h"

namespace i2p
{
namespace tunnel
{
	TunnelGatewayBuffer::TunnelGatewayBuffer ():
		m_CurrentTunnelDataMsg (nullptr), m_RemainingSize (0)
	{
		RAND_bytes (m_NonZeroRandomBuffer, TUNNEL_DATA_MAX_PAYLOAD_SIZE);
		for (size_t i = 0; i < TUNNEL_DATA_MAX_PAYLOAD_SIZE; i++)
			if (!m_NonZeroRandomBuffer[i]) m_NonZeroRandomBuffer[i] = 1;
	}

	TunnelGatewayBuffer::~TunnelGatewayBuffer ()
	{
		ClearTunnelDataMsgs ();
	}

	void TunnelGatewayBuffer::PutI2NPMsg (const TunnelMessageBlock& block)
	{
		bool messageCreated = false;
		if (!m_CurrentTunnelDataMsg)
		{
			CreateCurrentTunnelDataMessage ();
			messageCreated = true;
		}

		// create delivery instructions
		uint8_t di[43]; // max delivery instruction length is 43 for tunnel
		size_t diLen = 1;// flag
		if (block.deliveryType != eDeliveryTypeLocal) // tunnel or router
		{
			if (block.deliveryType == eDeliveryTypeTunnel)
			{
				htobe32buf (di + diLen, block.tunnelID);
				diLen += 4; // tunnelID
			}

			memcpy (di + diLen, block.hash, 32);
			diLen += 32; //len
		}
		di[0] = block.deliveryType << 5; // set delivery type

		// create fragments
		const std::shared_ptr<I2NPMessage> & msg = block.data;
		size_t fullMsgLen = diLen + msg->GetLength () + 2; // delivery instructions + payload + 2 bytes length

		if (!messageCreated && fullMsgLen > m_RemainingSize) // check if we should complete previous message
		{
			size_t numFollowOnFragments = fullMsgLen / TUNNEL_DATA_MAX_PAYLOAD_SIZE;
			// length of bytes doesn't fit full tunnel message
			// every follow-on fragment adds 7 bytes
			size_t nonFit = (fullMsgLen + numFollowOnFragments*7) % TUNNEL_DATA_MAX_PAYLOAD_SIZE;
			if (!nonFit || nonFit > m_RemainingSize || m_RemainingSize < fullMsgLen/5)
			{
				CompleteCurrentTunnelDataMessage ();
				CreateCurrentTunnelDataMessage ();
			}
		}
		if (fullMsgLen <= m_RemainingSize)
		{
			// message fits. First and last fragment
			htobe16buf (di + diLen, msg->GetLength ());
			diLen += 2; // size
			memcpy (m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len, di, diLen);
			memcpy (m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len + diLen, msg->GetBuffer (), msg->GetLength ());
			m_CurrentTunnelDataMsg->len += diLen + msg->GetLength ();
			m_RemainingSize -= diLen + msg->GetLength ();
			if (!m_RemainingSize)
				CompleteCurrentTunnelDataMessage ();
		}
		else
		{
			if (diLen + 6 <= m_RemainingSize)
			{
				// delivery instructions fit
				uint32_t msgID;
				memcpy (&msgID, msg->GetHeader () + I2NP_HEADER_MSGID_OFFSET, 4); // in network bytes order
				size_t size = m_RemainingSize - diLen - 6; // 6 = 4 (msgID) + 2 (size)

				// first fragment
				di[0] |= 0x08; // fragmented
				htobuf32 (di + diLen, msgID);
				diLen += 4; // Message ID
				htobe16buf (di + diLen, size);
				diLen += 2; // size
				memcpy (m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len, di, diLen);
				memcpy (m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len + diLen, msg->GetBuffer (), size);
				m_CurrentTunnelDataMsg->len += diLen + size;
				CompleteCurrentTunnelDataMessage ();
				// follow on fragments
				int fragmentNumber = 1;
				while (size < msg->GetLength ())
				{
					CreateCurrentTunnelDataMessage ();
					uint8_t * buf = m_CurrentTunnelDataMsg->GetBuffer ();
					buf[0] = 0x80 | (fragmentNumber << 1); // frag
					bool isLastFragment = false;
					size_t s = msg->GetLength () - size;
					if (s > TUNNEL_DATA_MAX_PAYLOAD_SIZE - 7) // 7 follow on instructions
						s = TUNNEL_DATA_MAX_PAYLOAD_SIZE - 7;
					else // last fragment
					{
						buf[0] |= 0x01;
						isLastFragment = true;
					}
					htobuf32 (buf + 1, msgID); //Message ID
					htobe16buf (buf + 5, s); // size
					memcpy (buf + 7, msg->GetBuffer () + size, s);
					m_CurrentTunnelDataMsg->len += s+7;
					if (isLastFragment)
					{
						if(m_RemainingSize < (s+7)) {
							LogPrint (eLogError, "TunnelGateway: remaining size overflow: ", m_RemainingSize, " < ", s+7);
						} else {
							m_RemainingSize -= s+7;
							if (m_RemainingSize == 0)
								CompleteCurrentTunnelDataMessage ();
						}
					}
					else
						CompleteCurrentTunnelDataMessage ();
					size += s;
					fragmentNumber++;
				}
			}
			else
			{
				// delivery instructions don't fit. Create new message
				CompleteCurrentTunnelDataMessage ();
				PutI2NPMsg (block);
				// don't delete msg because it's taken care inside
			}
		}
	}

	void TunnelGatewayBuffer::ClearTunnelDataMsgs ()
	{
		m_TunnelDataMsgs.clear ();
		m_CurrentTunnelDataMsg = nullptr;
	}

	void TunnelGatewayBuffer::CreateCurrentTunnelDataMessage ()
	{
		m_CurrentTunnelDataMsg = nullptr;
		m_CurrentTunnelDataMsg = NewI2NPShortMessage ();
		m_CurrentTunnelDataMsg->Align (12);
		// we reserve space for padding
		m_CurrentTunnelDataMsg->offset += TUNNEL_DATA_MSG_SIZE + I2NP_HEADER_SIZE;
		m_CurrentTunnelDataMsg->len = m_CurrentTunnelDataMsg->offset;
		m_RemainingSize = TUNNEL_DATA_MAX_PAYLOAD_SIZE;
	}

	void TunnelGatewayBuffer::CompleteCurrentTunnelDataMessage ()
	{
		if (!m_CurrentTunnelDataMsg) return;
		uint8_t * payload = m_CurrentTunnelDataMsg->GetBuffer ();
		size_t size = m_CurrentTunnelDataMsg->len - m_CurrentTunnelDataMsg->offset;

		m_CurrentTunnelDataMsg->offset = m_CurrentTunnelDataMsg->len - TUNNEL_DATA_MSG_SIZE - I2NP_HEADER_SIZE;
		uint8_t * buf = m_CurrentTunnelDataMsg->GetPayload ();
		RAND_bytes (buf + 4, 16); // original IV
		memcpy (payload + size, buf + 4, 16); // copy IV for checksum
		uint8_t hash[32];
		SHA256(payload, size+16, hash);
		memcpy (buf+20, hash, 4); // checksum
		payload[-1] = 0; // zero
		ptrdiff_t paddingSize = payload - buf - 25; // 25 = 24 + 1
		if (paddingSize > 0)
		{
			// non-zero padding
			auto randomOffset = rand () % (TUNNEL_DATA_MAX_PAYLOAD_SIZE - paddingSize + 1);
			memcpy (buf + 24, m_NonZeroRandomBuffer + randomOffset, paddingSize);
		}

		// we can't fill message header yet because encryption is required
		m_TunnelDataMsgs.push_back (m_CurrentTunnelDataMsg);
		m_CurrentTunnelDataMsg = nullptr;
	}

	void TunnelGateway::SendTunnelDataMsg (const TunnelMessageBlock& block)
	{
		if (block.data)
		{
			PutTunnelDataMsg (block);
			SendBuffer ();
		}
	}

	void TunnelGateway::PutTunnelDataMsg (const TunnelMessageBlock& block)
	{
		if (block.data)
			m_Buffer.PutI2NPMsg (block);
	}

	void TunnelGateway::SendBuffer ()
	{
		m_Buffer.CompleteCurrentTunnelDataMessage ();
		std::vector<std::shared_ptr<I2NPMessage> > newTunnelMsgs;
		const auto& tunnelDataMsgs = m_Buffer.GetTunnelDataMsgs ();
		for (auto& tunnelMsg : tunnelDataMsgs)
		{
			auto newMsg = CreateEmptyTunnelDataMsg ();
			m_Tunnel->EncryptTunnelMsg (tunnelMsg, newMsg);
			htobe32buf (newMsg->GetPayload (), m_Tunnel->GetNextTunnelID ());
			newMsg->FillI2NPMessageHeader (eI2NPTunnelData);
			newTunnelMsgs.push_back (newMsg);
			m_NumSentBytes += TUNNEL_DATA_MSG_SIZE;
		}
		m_Buffer.ClearTunnelDataMsgs ();
		i2p::transport::transports.SendMessages (m_Tunnel->GetNextIdentHash (), newTunnelMsgs);
	}
}
}
