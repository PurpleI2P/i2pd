/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TUNNEL_ENDPOINT_H__
#define TUNNEL_ENDPOINT_H__

#include <inttypes.h>
#include <vector>
#include <list>
#include <string>
#include <unordered_map>
#include <memory>
#include "I2NPProtocol.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{
	class TunnelEndpoint final
	{
		struct TunnelMessageBlockEx: public TunnelMessageBlock
		{
			uint64_t receiveTime; // milliseconds since epoch
			uint8_t nextFragmentNum;
		};

		struct Fragment
		{
			Fragment (bool last, uint64_t t, const uint8_t * buf, size_t size): 
				isLastFragment (last), receiveTime (t), data (size) { memcpy (data.data(), buf, size); };
			bool isLastFragment;
			uint64_t receiveTime; // milliseconds since epoch
			std::vector<uint8_t> data;
		};

		public:

			TunnelEndpoint (bool isInbound): m_IsInbound (isInbound), m_NumReceivedBytes (0), m_CurrentMsgID (0) {};
			~TunnelEndpoint () = default;
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			void Cleanup ();

			void HandleDecryptedTunnelDataMsg (std::shared_ptr<I2NPMessage> msg);
			void FlushI2NPMsgs (); 

			const i2p::data::IdentHash * GetCurrentHash () const; // return null if not available
			const std::unique_ptr<TunnelTransportSender>& GetSender () const { return m_Sender; };
		
		private:

			void HandleFollowOnFragment (uint32_t msgID, bool isLastFragment, uint8_t fragmentNum, const uint8_t * fragment, size_t size);
			bool ConcatFollowOnFragment (TunnelMessageBlockEx& msg, const uint8_t * fragment, size_t size) const; // true if success
			void HandleCurrenMessageFollowOnFragment (const uint8_t * fragment, size_t size, bool isLastFragment);
			void HandleNextMessage (const TunnelMessageBlock& msg);
			void SendMessageTo (const i2p::data::IdentHash& to, std::shared_ptr<i2p::I2NPMessage> msg);

			void AddOutOfSequenceFragment (uint32_t msgID, uint8_t fragmentNum, bool isLastFragment, const uint8_t * fragment, size_t size);
			bool ConcatNextOutOfSequenceFragment (uint32_t msgID, TunnelMessageBlockEx& msg); // true if something added
			void HandleOutOfSequenceFragments (uint32_t msgID, TunnelMessageBlockEx& msg);
			void AddIncompleteCurrentMessage ();

		private:

			std::unordered_map<uint32_t, TunnelMessageBlockEx> m_IncompleteMessages;
			std::unordered_map<uint64_t, Fragment> m_OutOfSequenceFragments; // ((msgID << 8) + fragment#)->fragment
			bool m_IsInbound;
			size_t m_NumReceivedBytes;
			TunnelMessageBlockEx m_CurrentMessage;
			uint32_t m_CurrentMsgID;
			// I2NP messages to send
			std::list<std::shared_ptr<i2p::I2NPMessage> > m_I2NPMsgs; // to send
			i2p::data::IdentHash m_CurrentHash; // send msgs to
			std::unique_ptr<TunnelTransportSender> m_Sender;
	};
}
}

#endif
