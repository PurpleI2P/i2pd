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
				std::shared_ptr<const i2p::data::RouterInfo::Address> addr);
			bool ProcessPeerTest (uint8_t * buf, size_t len) override;
			void Connect () override; // outgoing
			bool ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len) override; // incoming
			
		private:

			void SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen); // PeerTest message
			void SendPeerTest (uint8_t msg); // send or resend m_SignedData
			void HandlePeerTest (const uint8_t * buf, size_t len) override;

			void ScheduleResend ();
			
		private:

			uint8_t m_MsgNumReceived, m_NumResends;
			bool m_IsConnectedRecently, m_IsStatusChanged;
			std::vector<uint8_t> m_SignedData; // for resends
			boost::asio::deadline_timer m_PeerTestResendTimer;
	};	
}
}
	
#endif
