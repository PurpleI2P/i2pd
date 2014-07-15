#ifndef SSU_DATA_H__
#define SSU_DATA_H__

#include <inttypes.h>
#include <string.h>
#include <map>
#include <vector>
#include <set>
#include "I2NPProtocol.h"

namespace i2p
{
namespace ssu
{

	const size_t SSU_MTU = 1484;
	// data flags
	const uint8_t DATA_FLAG_EXTENDED_DATA_INCLUDED = 0x02;
	const uint8_t DATA_FLAG_WANT_REPLY = 0x04;
	const uint8_t DATA_FLAG_REQUEST_PREVIOUS_ACKS = 0x08;
	const uint8_t DATA_FLAG_EXPLICIT_CONGESTION_NOTIFICATION = 0x10;
	const uint8_t DATA_FLAG_ACK_BITFIELDS_INCLUDED = 0x40;
	const uint8_t DATA_FLAG_EXPLICIT_ACKS_INCLUDED = 0x80;	

	struct Fragment
	{
		int fragmentNum, len;
		bool isLast;
		uint8_t buf[SSU_MTU];

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
	
	class SSUSession;
	class SSUData
	{
		public:

			SSUData (SSUSession& session);
			~SSUData ();

			void ProcessMessage (uint8_t * buf, size_t len);
			void Send (i2p::I2NPMessage * msg);

		private:

			void SendMsgAck (uint32_t msgID);
			void SendFragmentAck (uint32_t msgID, int fragmentNum);
			void ProcessSentMessageAck (uint32_t msgID);	

		private:

			

			SSUSession& m_Session;
			std::map<uint32_t, IncompleteMessage *> m_IncomleteMessages;
			std::map<uint32_t, std::vector<uint8_t *> > m_SentMessages; // msgID -> fragments	
	};	
}
}

#endif

