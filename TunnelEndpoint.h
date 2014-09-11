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
			uint8_t nextFragmentNum;
		};	

		struct Fragment
		{
			uint8_t fragmentNum;
			bool isLastFragment;
			I2NPMessage * data;
		};	
		
		public:

			TunnelEndpoint (bool isInbound): m_IsInbound (isInbound), m_NumReceivedBytes (0) {};
			~TunnelEndpoint ();
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			
			void HandleDecryptedTunnelDataMsg (I2NPMessage * msg);

		private:

			void HandleFollowOnFragment (uint32_t msgID, bool isLastFragment, const TunnelMessageBlockEx& m);
			void HandleNextMessage (const TunnelMessageBlock& msg);

			void AddOutOfSequenceFragment (uint32_t msgID, uint8_t fragmentNum, bool isLastFragment, I2NPMessage * data);
			void HandleOutOfSequenceFragment (uint32_t msgID, TunnelMessageBlockEx& msg);
			
		private:			

			std::map<uint32_t, TunnelMessageBlockEx> m_IncompleteMessages;
			std::map<uint32_t, Fragment> m_OutOfSequenceFragments;
			bool m_IsInbound;
			size_t m_NumReceivedBytes;
	};	
}		
}

#endif
