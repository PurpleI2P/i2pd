#ifndef TUNNEL_BASE_H__
#define TUNNEL_BASE_H__

#include <inttypes.h>
#include <memory>
#include "Timestamp.h"
#include "DNNPProtocol.h"
#include "Identity.h"

namespace dotnet
{
namespace tunnel
{
	const size_t TUNNEL_DATA_MSG_SIZE = 1028;
	const size_t TUNNEL_DATA_ENCRYPTED_SIZE = 1008;
	const size_t TUNNEL_DATA_MAX_PAYLOAD_SIZE = 1003;

	enum TunnelDeliveryType
	{
		eDeliveryTypeLocal = 0,
		eDeliveryTypeTunnel = 1,
		eDeliveryTypeRouter = 2
	};
	struct TunnelMessageBlock
	{
		TunnelDeliveryType deliveryType;
		dotnet::data::IdentHash hash;
		uint32_t tunnelID;
		std::shared_ptr<DNNPMessage> data;
	};

	class TunnelBase
	{
		public:

			TunnelBase (uint32_t tunnelID, uint32_t nextTunnelID, dotnet::data::IdentHash nextIdent):
				m_TunnelID (tunnelID), m_NextTunnelID (nextTunnelID), m_NextIdent (nextIdent),
				m_CreationTime (dotnet::util::GetSecondsSinceEpoch ()) {};
			virtual ~TunnelBase () {};
			virtual void Cleanup () {};

			virtual void HandleTunnelDataMsg (std::shared_ptr<const dotnet::DNNPMessage> tunnelMsg) = 0;
			virtual void SendTunnelDataMsg (std::shared_ptr<dotnet::DNNPMessage> msg) = 0;
			virtual void FlushTunnelDataMsgs () {};
			virtual void EncryptTunnelMsg (std::shared_ptr<const DNNPMessage> in, std::shared_ptr<DNNPMessage> out) = 0;
			uint32_t GetNextTunnelID () const { return m_NextTunnelID; };
			const dotnet::data::IdentHash& GetNextIdentHash () const { return m_NextIdent; };
			virtual uint32_t GetTunnelID () const { return m_TunnelID; }; // as known at our side

			uint32_t GetCreationTime () const { return m_CreationTime; };
			void SetCreationTime (uint32_t t) { m_CreationTime = t; };

		private:

			uint32_t m_TunnelID, m_NextTunnelID;
			dotnet::data::IdentHash m_NextIdent;
			uint32_t m_CreationTime; // seconds since epoch
	};

	struct TunnelCreationTimeCmp
	{
		template<typename T>
		bool operator() (const std::shared_ptr<T> & t1, const std::shared_ptr<T> & t2) const
		{
			if (t1->GetCreationTime () != t2->GetCreationTime ())
				return t1->GetCreationTime () > t2->GetCreationTime ();
			else
				return t1 < t2;
		}
	};
}
}

#endif
