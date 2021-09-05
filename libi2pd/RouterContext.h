/*
* Copyright (c) 2013-2021, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef ROUTER_CONTEXT_H__
#define ROUTER_CONTEXT_H__

#include <inttypes.h>
#include <string>
#include <memory>
#include <mutex>
#include <chrono>
#include <boost/asio.hpp>
#include "Identity.h"
#include "RouterInfo.h"
#include "Garlic.h"

namespace i2p
{
namespace garlic
{
	class RouterIncomingRatchetSession;
}

	const char ROUTER_INFO[] = "router.info";
	const char ROUTER_KEYS[] = "router.keys";
	const char NTCP2_KEYS[] = "ntcp2.keys";
	const int ROUTER_INFO_UPDATE_INTERVAL = 1800; // 30 minutes

	enum RouterStatus
	{
		eRouterStatusOK = 0,
		eRouterStatusTesting = 1,
		eRouterStatusFirewalled = 2,
		eRouterStatusError = 3,
		eRouterStatusUnknown = 4,
		eRouterStatusProxy = 5,
		eRouterStatusMesh = 6
	};

	enum RouterError
	{
		eRouterErrorNone = 0,
		eRouterErrorClockSkew = 1,
		eRouterErrorOffline = 2,
		eRouterErrorSymmetricNAT = 3
	};

	class RouterContext: public i2p::garlic::GarlicDestination
	{
		private:

			struct NTCP2PrivateKeys
			{
				uint8_t staticPublicKey[32];
				uint8_t staticPrivateKey[32];
				uint8_t iv[16];
			};

		public:

			RouterContext ();
			void Init ();

			const i2p::data::PrivateKeys& GetPrivateKeys () const { return m_Keys; };
			i2p::data::RouterInfo& GetRouterInfo () { return m_RouterInfo; };		
			std::shared_ptr<i2p::data::RouterInfo> GetSharedRouterInfo ()
			{
				return std::shared_ptr<i2p::data::RouterInfo> (&m_RouterInfo,
					[](i2p::data::RouterInfo *) {});
			}
			std::shared_ptr<i2p::garlic::GarlicDestination> GetSharedDestination ()
			{
				return std::shared_ptr<i2p::garlic::GarlicDestination> (this,
					[](i2p::garlic::GarlicDestination *) {});
			}
			const uint8_t * GetNTCP2StaticPublicKey () const { return m_NTCP2Keys ? m_NTCP2Keys->staticPublicKey : nullptr; };
			const uint8_t * GetNTCP2StaticPrivateKey () const { return m_NTCP2Keys ? m_NTCP2Keys->staticPrivateKey : nullptr; };
			const uint8_t * GetNTCP2IV () const { return m_NTCP2Keys ? m_NTCP2Keys->iv : nullptr; };
			i2p::crypto::X25519Keys& GetStaticKeys ();

			uint32_t GetUptime () const; // in seconds
			uint64_t GetLastUpdateTime () const { return m_LastUpdateTime; };
			uint64_t GetBandwidthLimit () const { return m_BandwidthLimit; };
			uint64_t GetTransitBandwidthLimit () const { return (m_BandwidthLimit*m_ShareRatio)/100LL; };
			RouterStatus GetStatus () const { return m_Status; };
			void SetStatus (RouterStatus status);
			RouterError GetError () const { return m_Error; };
			void SetError (RouterError error) { m_Status = eRouterStatusError; m_Error = error; };
			RouterStatus GetStatusV6 () const { return m_StatusV6; };
			void SetStatusV6 (RouterStatus status);
			int GetNetID () const { return m_NetID; };
			void SetNetID (int netID) { m_NetID = netID; };
			bool DecryptTunnelBuildRecord (const uint8_t * encrypted, uint8_t * data);
			bool DecryptTunnelShortRequestRecord (const uint8_t * encrypted, uint8_t * data);
			
			void UpdatePort (int port); // called from Daemon
			void UpdateAddress (const boost::asio::ip::address& host); // called from SSU or Daemon
			void PublishNTCP2Address (int port, bool publish, bool v4, bool v6, bool ygg);
			void UpdateNTCP2Address (bool enable);
			void RemoveNTCPAddress (bool v4only = true); // delete NTCP address for older routers. TODO: remove later
			bool AddIntroducer (const i2p::data::RouterInfo::Introducer& introducer);
			void RemoveIntroducer (const boost::asio::ip::udp::endpoint& e);
			bool IsUnreachable () const;
			void SetUnreachable (bool v4, bool v6);
			void SetReachable (bool v4, bool v6);
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
			bool SupportsMesh () const { return m_RouterInfo.IsMesh (); };
			void SetSupportsV6 (bool supportsV6);
			void SetSupportsV4 (bool supportsV4);
			void SetSupportsMesh (bool supportsmesh, const boost::asio::ip::address_v6& host);
			i2p::crypto::NoiseSymmetricState& GetCurrentNoiseState () { return m_CurrentNoiseState; };

			void UpdateNTCP2V6Address (const boost::asio::ip::address& host); // called from Daemon. TODO: remove
			void UpdateStats ();
			void UpdateTimestamp (uint64_t ts); // in seconds, called from NetDb before publishing
			void CleanupDestination (); // garlic destination

			// implements LocalDestination
			std::shared_ptr<const i2p::data::IdentityEx> GetIdentity () const { return m_Keys.GetPublic (); };
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, i2p::data::CryptoKeyType preferredCrypto) const;
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const { m_Keys.Sign (buf, len, signature); };
			void SetLeaseSetUpdated () {};

			// implements GarlicDestination
			std::shared_ptr<const i2p::data::LocalLeaseSet> GetLeaseSet () { return nullptr; };
			std::shared_ptr<i2p::tunnel::TunnelPool> GetTunnelPool () const;

			// override GarlicDestination
			void ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg);
			void ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg);

		protected:

			// implements GarlicDestination
			void HandleI2NPMessage (const uint8_t * buf, size_t len);
			bool HandleCloveI2NPMessage (I2NPMessageType typeID, const uint8_t * payload, size_t len, uint32_t msgID);

		private:

			void CreateNewRouter ();
			void NewRouterInfo ();
			void UpdateRouterInfo ();
			void NewNTCP2Keys ();
			bool Load ();
			void SaveKeys ();

			bool DecryptECIESTunnelBuildRecord (const uint8_t * encrypted, uint8_t * data, size_t clearTextSize);
			
		private:

			i2p::data::RouterInfo m_RouterInfo;
			i2p::data::PrivateKeys m_Keys;
			std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> m_Decryptor, m_TunnelDecryptor;
			std::shared_ptr<i2p::garlic::RouterIncomingRatchetSession> m_ECIESSession;
			uint64_t m_LastUpdateTime; // in seconds
			bool m_AcceptsTunnels, m_IsFloodfill;
			std::chrono::time_point<std::chrono::steady_clock> m_StartupTime;
			uint64_t m_BandwidthLimit; // allowed bandwidth
			int m_ShareRatio;
			RouterStatus m_Status, m_StatusV6;
			RouterError m_Error;
			int m_NetID;
			std::mutex m_GarlicMutex;
			std::unique_ptr<NTCP2PrivateKeys> m_NTCP2Keys;
			std::unique_ptr<i2p::crypto::X25519Keys> m_StaticKeys;
			// for ECIESx25519
			i2p::crypto::NoiseSymmetricState m_InitialNoiseState, m_CurrentNoiseState;
	};

	extern RouterContext context;
}

#endif
