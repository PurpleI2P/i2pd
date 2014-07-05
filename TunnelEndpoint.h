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
		
		public:

			TunnelEndpoint (): m_NumReceivedBytes (0) {};
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			
			void HandleDecryptedTunnelDataMsg (I2NPMessage * msg);

		private:

			void HandleFollowOnFragment (uint32_t msgID, bool isLastFragment, const TunnelMessageBlockEx& m);
			void HandleNextMessage (const TunnelMessageBlock& msg);
			
		private:			

			std::map<uint32_t, TunnelMessageBlockEx> m_IncompleteMessages;
			size_t m_NumReceivedBytes;
	};	
}		
}

#endif
