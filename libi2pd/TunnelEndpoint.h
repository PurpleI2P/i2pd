/*
* Copyright (c) 2013-2021, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TUNNEL_ENDPOINT_H__
#define TUNNEL_ENDPOINT_H__

#include <inttypes.h>
#include <vector>
#include <string>
#include <unordered_map>
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
			Fragment (bool last, uint64_t t, size_t size): isLastFragment (last), receiveTime (t), data (size) {};
			bool isLastFragment;
			uint64_t receiveTime; // milliseconds since epoch
			std::vector<uint8_t> data;
		};

		public:

			TunnelEndpoint (bool isInbound): m_IsInbound (isInbound), m_NumReceivedBytes (0), m_CurrentMsgID (0) {};
			~TunnelEndpoint ();
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			void Cleanup ();

			void HandleDecryptedTunnelDataMsg (std::shared_ptr<I2NPMessage> msg);

		private:

			void HandleFollowOnFragment (uint32_t msgID, bool isLastFragment, uint8_t fragmentNum, const uint8_t * fragment, size_t size);
			bool ConcatFollowOnFragment (TunnelMessageBlockEx& msg, const uint8_t * fragment, size_t size) const; // true if success
			void HandleCurrenMessageFollowOnFragment (const uint8_t * fragment, size_t size, bool isLastFragment);
			void HandleNextMessage (const TunnelMessageBlock& msg);

			void AddOutOfSequenceFragment (uint32_t msgID, uint8_t fragmentNum, bool isLastFragment, const uint8_t * fragment, size_t size);
			bool ConcatNextOutOfSequenceFragment (uint32_t msgID, TunnelMessageBlockEx& msg); // true if something added
			void HandleOutOfSequenceFragments (uint32_t msgID, TunnelMessageBlockEx& msg);
			void AddIncompleteCurrentMessage ();

		private:

			std::unordered_map<uint32_t, TunnelMessageBlockEx> m_IncompleteMessages;
			std::unordered_map<uint64_t, std::unique_ptr<Fragment> > m_OutOfSequenceFragments; // ((msgID << 8) + fragment#)->fragment
			bool m_IsInbound;
			size_t m_NumReceivedBytes;
			TunnelMessageBlockEx m_CurrentMessage;
			uint32_t m_CurrentMsgID;
	};
}
}

#endif
