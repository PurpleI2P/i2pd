#ifndef NTCP2_H__
#define NTCP2_H__

#include <inttypes.h>
#include <memory>
#include "RouterInfo.h"
#include "TransportSession.h"

namespace i2p
{
namespace transport
{
	class NTCP2Session: public TransportSession, public std::enable_shared_from_this<NTCP2Session>
	{
		public:

			NTCP2Session (std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr); // TODO
			~NTCP2Session ();

		private:

			void CreateEphemeralKey (uint8_t * pub);
			void SendSessionRequest (const uint8_t * iv);

		private:

			uint8_t m_ExpandedPrivateKey[64]; // x25519 ephemeral key
	};
}
}

#endif
