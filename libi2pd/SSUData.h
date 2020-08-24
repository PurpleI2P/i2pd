/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU_DATA_H__
#define SSU_DATA_H__

#include <inttypes.h>
#include <string.h>
#include <unordered_map>
#include <vector>
#include <unordered_set>
#include <memory>
#include <boost/asio.hpp>
#include "I2NPProtocol.h"
#include "Identity.h"
#include "RouterInfo.h"

namespace i2p
{
namespace transport
{

	const size_t SSU_MTU_V4 = 1484;
	#ifdef MESHNET
	const size_t SSU_MTU_V6 = 1286;
	#else
	const size_t SSU_MTU_V6 = 1488;
	#endif
	const size_t IPV4_HEADER_SIZE = 20;
	const size_t IPV6_HEADER_SIZE = 40;
	const size_t UDP_HEADER_SIZE = 8;
	const size_t SSU_V4_MAX_PACKET_SIZE = SSU_MTU_V4 - IPV4_HEADER_SIZE - UDP_HEADER_SIZE; // 1456
	const size_t SSU_V6_MAX_PACKET_SIZE = SSU_MTU_V6 - IPV6_HEADER_SIZE - UDP_HEADER_SIZE; // 1440
	const int RESEND_INTERVAL = 3; // in seconds
	const int MAX_NUM_RESENDS = 5;
	const int DECAY_INTERVAL = 20; // in seconds
	const int INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT = 30; // in seconds
	const unsigned int MAX_NUM_RECEIVED_MESSAGES = 1000; // how many msgID we store for duplicates check
	const int MAX_OUTGOING_WINDOW_SIZE = 200; // how many unacked message we can store
	// data flags
	const uint8_t DATA_FLAG_EXTENDED_DATA_INCLUDED = 0x02;
	const uint8_t DATA_FLAG_WANT_REPLY = 0x04;
	const uint8_t DATA_FLAG_REQUEST_PREVIOUS_ACKS = 0x08;
	const uint8_t DATA_FLAG_EXPLICIT_CONGESTION_NOTIFICATION = 0x10;
	const uint8_t DATA_FLAG_ACK_BITFIELDS_INCLUDED = 0x40;
	const uint8_t DATA_FLAG_EXPLICIT_ACKS_INCLUDED = 0x80;

	struct Fragment
	{
		int fragmentNum;
		size_t len;
		bool isLast;
		uint8_t buf[SSU_V4_MAX_PACKET_SIZE + 18]; // use biggest

		Fragment () = default;
		Fragment (int n, const uint8_t * b, int l, bool last):
			fragmentNum (n), len (l), isLast (last) { memcpy (buf, b, len); };
	};

	struct FragmentCmp
	{
		bool operator() (const std::unique_ptr<Fragment>& f1, const std::unique_ptr<Fragment>& f2) const
		{
			return f1->fragmentNum < f2->fragmentNum;
		};
	};

	struct IncompleteMessage
	{
		std::shared_ptr<I2NPMessage> msg;
		int nextFragmentNum;
		uint32_t lastFragmentInsertTime; // in seconds
		std::set<std::unique_ptr<Fragment>, FragmentCmp> savedFragments;

		IncompleteMessage (std::shared_ptr<I2NPMessage> m): msg (m), nextFragmentNum (0), lastFragmentInsertTime (0) {};
		void AttachNextFragment (const uint8_t * fragment, size_t fragmentSize);
	};

	struct SentMessage
	{
		std::vector<std::unique_ptr<Fragment> > fragments;
		uint32_t nextResendTime; // in seconds
		int numResends;
	};

	class SSUSession;
	class SSUData
	{
		public:

			SSUData (SSUSession& session);
			~SSUData ();

			void Start ();
			void Stop ();

			void ProcessMessage (uint8_t * buf, size_t len);
			void FlushReceivedMessage ();
			void Send (std::shared_ptr<i2p::I2NPMessage> msg);

			void AdjustPacketSize (std::shared_ptr<const i2p::data::RouterInfo> remoteRouter);
			void UpdatePacketSize (const i2p::data::IdentHash& remoteIdent);

		private:

			void SendMsgAck (uint32_t msgID);
			void SendFragmentAck (uint32_t msgID, int fragmentNum);
			void ProcessAcks (uint8_t *& buf, uint8_t flag);
			void ProcessFragments (uint8_t * buf);
			void ProcessSentMessageAck (uint32_t msgID);

			void ScheduleResend ();
			void HandleResendTimer (const boost::system::error_code& ecode);

			void ScheduleIncompleteMessagesCleanup ();
			void HandleIncompleteMessagesCleanupTimer (const boost::system::error_code& ecode);


		private:

			SSUSession& m_Session;
			std::unordered_map<uint32_t, std::unique_ptr<IncompleteMessage> > m_IncompleteMessages;
			std::unordered_map<uint32_t, std::unique_ptr<SentMessage> > m_SentMessages;
			std::unordered_set<uint32_t> m_ReceivedMessages;
			boost::asio::deadline_timer m_ResendTimer, m_IncompleteMessagesCleanupTimer;
			int m_MaxPacketSize, m_PacketSize;
			i2p::I2NPMessagesHandler m_Handler;
			uint32_t m_LastMessageReceivedTime; // in second
	};
}
}

#endif
