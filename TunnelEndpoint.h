#ifndef TUNNEL_ENDPOINT_H__
#define TUNNEL_ENDPOINT_H__

#include <inttypes.h>
#include <map>
#include <string>
#include "I2NPProtocol.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{
	class TunnelEndpoint
	{	
		struct TunnelMessageBlockEx: public TunnelMessageBlock
		{
			uint64_t receiveTime; // milliseconds since epoch
			uint8_t nextFragmentNum;
		};	

		struct Fragment
		{
			bool isLastFragment;
			std::shared_ptr<I2NPMessage> data;
			uint64_t receiveTime; // milliseconds since epoch
		};	
		
		public:

			TunnelEndpoint (bool isInbound): m_IsInbound (isInbound), m_NumReceivedBytes (0) {};
			~TunnelEndpoint ();
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			void Cleanup ();			

			void HandleDecryptedTunnelDataMsg (std::shared_ptr<I2NPMessage> msg);

		private:

			void HandleFollowOnFragment (uint32_t msgID, bool isLastFragment, const TunnelMessageBlockEx& m);
			void HandleNextMessage (const TunnelMessageBlock& msg);

			void AddOutOfSequenceFragment (uint32_t msgID, uint8_t fragmentNum, bool isLastFragment, std::shared_ptr<I2NPMessage> data);
			bool ConcatNextOutOfSequenceFragment (uint32_t msgID, TunnelMessageBlockEx& msg); // true if something added
			void HandleOutOfSequenceFragments (uint32_t msgID, TunnelMessageBlockEx& msg);			

		private:			

			std::map<uint32_t, TunnelMessageBlockEx> m_IncompleteMessages;
			std::map<std::pair<uint32_t, uint8_t>, Fragment> m_OutOfSequenceFragments; // (msgID, fragment#)->fragment
			bool m_IsInbound;
			size_t m_NumReceivedBytes;
	};	
}		
}

#endif
