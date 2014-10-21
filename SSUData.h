#ifndef SSU_DATA_H__
#define SSU_DATA_H__

#include <inttypes.h>
#include <string.h>
#include <map>
#include <vector>
#include <set>
#include <boost/asio.hpp>
#include "I2NPProtocol.h"
#include "Identity.h"
#include "RouterInfo.h"

namespace i2p
{
namespace transport
{

	const size_t SSU_MTU = 1484;
	const size_t IPV4_HEADER_SIZE = 20;
	const size_t UDP_HEADER_SIZE = 8;
	const size_t SSU_MAX_PACKET_SIZE = SSU_MTU - IPV4_HEADER_SIZE - UDP_HEADER_SIZE; // 1456
	const int RESEND_INTERVAL = 3; // in seconds
	const int MAX_NUM_RESENDS = 5;
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
		uint8_t buf[SSU_MAX_PACKET_SIZE + 18];

		Fragment () = default;
		Fragment (int n, const uint8_t * b, int l, bool last): 
			fragmentNum (n), len (l), isLast (last) { memcpy (buf, b, len); };		
	};	

	struct FragmentCmp
	{
		bool operator() (const Fragment * f1, const Fragment * f2) const
  		{	
			return f1->fragmentNum < f2->fragmentNum; 
		};
	};	
	
	struct IncompleteMessage
	{
		I2NPMessage * msg;
		int nextFragmentNum;	
		std::set<Fragment *, FragmentCmp> savedFragments;
		
		IncompleteMessage (I2NPMessage * m): msg (m), nextFragmentNum (0) {};
		~IncompleteMessage () { for (auto it: savedFragments) { delete it; }; };
	};

	struct SentMessage
	{
		std::vector<Fragment *> fragments;
		uint32_t nextResendTime; // in seconds
		int numResends;

		~SentMessage () { for (auto it: fragments) { delete it; }; };
	};	
	
	class SSUSession;
	class SSUData
	{
		public:

			SSUData (SSUSession& session);
			~SSUData ();

			void ProcessMessage (uint8_t * buf, size_t len);
			void Send (i2p::I2NPMessage * msg);

			void UpdatePacketSize (const i2p::data::IdentHash& remoteIdent);

		private:

			void SendMsgAck (uint32_t msgID);
			void SendFragmentAck (uint32_t msgID, int fragmentNum);
			void ProcessAcks (uint8_t *& buf, uint8_t flag);
			void ProcessFragments (uint8_t * buf);
			void ProcessSentMessageAck (uint32_t msgID);	

			void ScheduleResend ();
			void HandleResendTimer (const boost::system::error_code& ecode);	
			
			void AdjustPacketSize (const i2p::data::RouterInfo& remoteRouter);	
			
		private:	

			SSUSession& m_Session;
			std::map<uint32_t, IncompleteMessage *> m_IncomleteMessages;
			std::map<uint32_t, SentMessage *> m_SentMessages;
			std::set<uint32_t> m_ReceivedMessages;
			boost::asio::deadline_timer m_ResendTimer;
			int m_PacketSize;
	};	
}
}

#endif

