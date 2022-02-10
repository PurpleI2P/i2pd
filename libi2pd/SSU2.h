/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU2_H__
#define SSU2_H__

#include <memory>
#include "Crypto.h"
#include "RouterInfo.h"
#include "TransportSession.h"

namespace i2p
{
namespace transport
{
	const int SSU2_TERMINATION_TIMEOUT = 330; // 5.5 minutes
	
	class SSU2Session: public TransportSession, public std::enable_shared_from_this<SSU2Session>
	{
		public:

			SSU2Session (std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr,
				std::shared_ptr<const i2p::data::RouterInfo::Address> addr = nullptr, bool peerTest = false);
			~SSU2Session ();

		private:

			void SendSessionRequest ();
			void EncryptHeader (i2p::crypto::ChipherBlock& header);
			void CreateHeaderMask (const uint8_t * kh1, const uint8_t * nonce1, const uint8_t * kh2, const uint8_t * nonce2);
		
		private:

			std::shared_ptr<i2p::crypto::X25519Keys> m_EphemeralKeys;
			std::unique_ptr<i2p::crypto::NoiseSymmetricState> m_NoiseState;
			std::shared_ptr<const i2p::data::RouterInfo::Address> m_Address;

			i2p::crypto::ChipherBlock m_HeaderMask;
	};
}
}

#endif
