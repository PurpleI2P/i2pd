/*
* Copyright (c) 2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU2_OUT_OF_SESSION_H__
#define SSU2_OUT_OF_SESSION_H__

#include <vector>
#include "SSU2Session.h"

namespace i2p
{
namespace transport
{
	const int SSU2_PEER_TEST_RESEND_INTERVAL = 3000; // in milliseconds
	const int SSU2_PEER_TEST_RESEND_INTERVAL_VARIANCE = 2000; // in milliseconds
	const int SSU2_PEER_TEST_MAX_NUM_RESENDS = 3;
	
	class SSU2PeerTestSession: public SSU2Session // for PeerTest msgs 5,6,7
	{
		public:

			SSU2PeerTestSession (SSU2Server& server, uint64_t sourceConnID, uint64_t destConnID);

			uint8_t GetMsgNumReceived () const { return m_MsgNumReceived; }	
			bool IsConnectedRecently () const { return m_IsConnectedRecently; }
			void SetStatusChanged () { m_IsStatusChanged = true; }
			
			void SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen, 
				std::shared_ptr<const i2p::data::RouterInfo::Address> addr, bool delayed = false);
			bool ProcessPeerTest (uint8_t * buf, size_t len) override;
			void Connect () override; // outgoing
			bool ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len) override; // incoming
			
		private:

			void SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen, bool delayed = false); // PeerTest message
			void SendPeerTest (uint8_t msg); // send or resend m_SignedData
			void HandlePeerTest (const uint8_t * buf, size_t len) override;
			void HandleAddress (const uint8_t * buf, size_t len) override;

			void ScheduleResend (uint8_t msg);
			
		private:

			uint8_t m_MsgNumReceived, m_NumResends;
			bool m_IsConnectedRecently, m_IsStatusChanged;
			std::vector<uint8_t> m_SignedData; // for resends
			boost::asio::deadline_timer m_PeerTestResendTimer;
			boost::asio::ip::udp::endpoint m_OurEndpoint; // as seen by peer
	};	

	const int SSU2_HOLE_PUNCH_RESEND_INTERVAL = 1000; // in milliseconds
	const int SSU2_HOLE_PUNCH_RESEND_INTERVAL_VARIANCE = 500; // in milliseconds
	const int SSU2_HOLE_PUNCH_MAX_NUM_RESENDS = 3;
	
	class SSU2HolePunchSession: public SSU2Session // Charlie
	{
		public:

			SSU2HolePunchSession (SSU2Server& server, uint32_t nonce, const boost::asio::ip::udp::endpoint& remoteEndpoint,
				std::shared_ptr<const i2p::data::RouterInfo::Address> addr);

			void SendHolePunch (const uint8_t * relayResponseBlock, size_t relayResponseBlockLen);

			bool ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len) override; // SessionRequest
			
		private:
			
			void SendHolePunch ();
			void ScheduleResend ();
			
		private:

			int m_NumResends;
			std::vector<uint8_t> m_RelayResponseBlock;
			boost::asio::deadline_timer m_HolePunchResendTimer;
	};	
}
}
	
#endif
