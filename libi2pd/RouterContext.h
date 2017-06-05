#ifndef ROUTER_CONTEXT_H__
#define ROUTER_CONTEXT_H__

#include <inttypes.h>
#include <string>
#include <memory>
#include <mutex>
#include <boost/asio.hpp>
#include "Identity.h"
#include "RouterInfo.h"
#include "Garlic.h"

namespace i2p
{
	const char ROUTER_INFO[] = "router.info";
	const char ROUTER_KEYS[] = "router.keys";	
	const int ROUTER_INFO_UPDATE_INTERVAL = 1800; // 30 minutes

	enum RouterStatus
	{
		eRouterStatusOK = 0,
		eRouterStatusTesting = 1,
		eRouterStatusFirewalled = 2,
		eRouterStatusError = 3 
	};	

	enum RouterError
	{
		eRouterErrorNone = 0,
		eRouterErrorClockSkew = 1
	};	
	
	class RouterContext: public i2p::garlic::GarlicDestination 
	{
		public:

			RouterContext ();
			void Init ();

			const i2p::data::PrivateKeys& GetPrivateKeys () const { return m_Keys; };
			i2p::data::RouterInfo& GetRouterInfo () { return m_RouterInfo; };
			std::shared_ptr<const i2p::data::RouterInfo> GetSharedRouterInfo () const 
			{ 
				return std::shared_ptr<const i2p::data::RouterInfo> (&m_RouterInfo, 
					[](const i2p::data::RouterInfo *) {});
			}
			std::shared_ptr<i2p::garlic::GarlicDestination> GetSharedDestination () 
			{
				return std::shared_ptr<i2p::garlic::GarlicDestination> (this, 
					[](i2p::garlic::GarlicDestination *) {});
			}

			uint32_t GetUptime () const;
			uint32_t GetStartupTime () const { return m_StartupTime; };
			uint64_t GetLastUpdateTime () const { return m_LastUpdateTime; };
			uint64_t GetBandwidthLimit () const { return m_BandwidthLimit; };
			uint64_t GetTransitBandwidthLimit () const { return (m_BandwidthLimit*m_ShareRatio)/100LL; };
			RouterStatus GetStatus () const { return m_Status; };
			void SetStatus (RouterStatus status);
			RouterError GetError () const { return m_Error; };
			void SetError (RouterError error) { m_Status = eRouterStatusError; m_Error = error; };
			int GetNetID () const { return m_NetID; };
			void SetNetID (int netID) { m_NetID = netID; };			

			void UpdatePort (int port); // called from Daemon
			void UpdateAddress (const boost::asio::ip::address& host);	// called from SSU or Daemon
			bool AddIntroducer (const i2p::data::RouterInfo::Introducer& introducer);
			void RemoveIntroducer (const boost::asio::ip::udp::endpoint& e);
			bool IsUnreachable () const;
			void SetUnreachable ();		
			void SetReachable ();
			bool IsFloodfill () const { return m_IsFloodfill; };	
			void SetFloodfill (bool floodfill);	
			void SetFamily (const std::string& family);
			std::string GetFamily () const;
			void SetBandwidth (int limit); /* in kilobytes */
			void SetBandwidth (char L); /* by letter */
			void SetShareRatio (int percents); // 0 - 100
			bool AcceptsTunnels () const { return m_AcceptsTunnels; };
			void SetAcceptsTunnels (bool acceptsTunnels) { m_AcceptsTunnels = acceptsTunnels; };
			bool SupportsV6 () const { return m_RouterInfo.IsV6 (); };
			bool SupportsV4 () const { return m_RouterInfo.IsV4 (); };
			void SetSupportsV6 (bool supportsV6);
			void SetSupportsV4 (bool supportsV4);

			void UpdateNTCPV6Address (const boost::asio::ip::address& host); // called from NTCP session		
			void UpdateStats ();	
			void CleanupDestination ();	// garlic destination

			// implements LocalDestination
			std::shared_ptr<const i2p::data::IdentityEx> GetIdentity () const { return m_Keys.GetPublic (); };
			const uint8_t * GetEncryptionPrivateKey () const { return m_Keys.GetPrivateKey (); };
			const uint8_t * GetEncryptionPublicKey () const { return GetIdentity ()->GetStandardIdentity ().publicKey; };
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const { m_Keys.Sign (buf, len, signature); }; 
			void SetLeaseSetUpdated () {};

			// implements GarlicDestination
			std::shared_ptr<const i2p::data::LocalLeaseSet> GetLeaseSet () { return nullptr; };
			std::shared_ptr<i2p::tunnel::TunnelPool> GetTunnelPool () const;
			void HandleI2NPMessage (const uint8_t * buf, size_t len, std::shared_ptr<i2p::tunnel::InboundTunnel> from);

			// override GarlicDestination
			void ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg);
			void ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg);	
			
		private:

			void CreateNewRouter ();
			void NewRouterInfo ();
			void UpdateRouterInfo ();
			bool Load ();
			void SaveKeys ();
			
		private:

			i2p::data::RouterInfo m_RouterInfo;
			i2p::data::PrivateKeys m_Keys; 
			uint64_t m_LastUpdateTime;
			bool m_AcceptsTunnels, m_IsFloodfill;
			uint64_t m_StartupTime; // in seconds since epoch
			uint64_t m_BandwidthLimit; // allowed bandwidth
			int m_ShareRatio;
			RouterStatus m_Status;
			RouterError m_Error;
			int m_NetID;
			std::mutex m_GarlicMutex;
	};

	extern RouterContext context;
}	

#endif
