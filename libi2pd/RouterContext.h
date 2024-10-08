/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
#include <unordered_set>
#include <boost/asio.hpp>
#include "Identity.h"
#include "RouterInfo.h"
#include "Garlic.h"
#include "util.h"

namespace i2p
{
namespace garlic
{
	class RouterIncomingRatchetSession;
}

	const char ROUTER_INFO[] = "router.info";
	const char ROUTER_KEYS[] = "router.keys";
	const char NTCP2_KEYS[] = "ntcp2.keys";
	const char SSU2_KEYS[] = "ssu2.keys";
	const int ROUTER_INFO_UPDATE_INTERVAL = 30*60; // 30 minutes
	const int ROUTER_INFO_PUBLISH_INTERVAL = 39*60; // in seconds
	const int ROUTER_INFO_INITIAL_PUBLISH_INTERVAL = 10; // in seconds
	const int ROUTER_INFO_PUBLISH_INTERVAL_VARIANCE = 105;// in seconds
	const int ROUTER_INFO_CONFIRMATION_TIMEOUT = 5; // in seconds
	const int ROUTER_INFO_MAX_PUBLISH_EXCLUDED_FLOODFILLS = 15;
	const int ROUTER_INFO_CONGESTION_UPDATE_INTERVAL = 12*60; // in seconds
	const int ROUTER_INFO_CLEANUP_INTERVAL = 5; // in minutes

	enum RouterStatus
	{
		eRouterStatusOK = 0,
		eRouterStatusFirewalled = 1,
		eRouterStatusUnknown = 2,
		eRouterStatusProxy = 3,
		eRouterStatusMesh = 4
	};

	const char* const ROUTER_STATUS_NAMES[] =
	{
		"OK", // 0
		"Firewalled", // 1
		"Unknown", // 2
		"Proxy", // 3
		"Mesh" // 4
	};

	enum RouterError
	{
		eRouterErrorNone = 0,
		eRouterErrorClockSkew = 1,
		eRouterErrorOffline = 2,
		eRouterErrorSymmetricNAT = 3,
		eRouterErrorFullConeNAT = 4,
		eRouterErrorNoDescriptors = 5
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

			struct SSU2PrivateKeys
			{
				uint8_t staticPublicKey[32];
				uint8_t staticPrivateKey[32];
				uint8_t intro[32];
			};

			class RouterService: public i2p::util::RunnableServiceWithWork
			{
				public:

					RouterService (): RunnableServiceWithWork ("Router") {};
					boost::asio::io_service& GetService () { return GetIOService (); };
					void Start () { StartIOService (); };
					void Stop () { StopIOService (); };
			};
			
		public:

			RouterContext ();
			void Init ();
			void Start ();
			void Stop ();
			
			const i2p::data::PrivateKeys& GetPrivateKeys () const { return m_Keys; };
			i2p::data::LocalRouterInfo& GetRouterInfo () { return m_RouterInfo; };
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
			std::shared_ptr<i2p::data::RouterInfo::Buffer> CopyRouterInfoBuffer () const;
			
			const uint8_t * GetNTCP2StaticPublicKey () const { return m_NTCP2Keys ? m_NTCP2Keys->staticPublicKey : nullptr; };
			const uint8_t * GetNTCP2StaticPrivateKey () const { return m_NTCP2Keys ? m_NTCP2Keys->staticPrivateKey : nullptr; };
			const uint8_t * GetNTCP2IV () const { return m_NTCP2Keys ? m_NTCP2Keys->iv : nullptr; };
			i2p::crypto::X25519Keys& GetNTCP2StaticKeys ();

			const uint8_t * GetSSU2StaticPublicKey () const { return m_SSU2Keys ? m_SSU2Keys->staticPublicKey : nullptr; };
			const uint8_t * GetSSU2StaticPrivateKey () const { return m_SSU2Keys ? m_SSU2Keys->staticPrivateKey : nullptr; };
			const uint8_t * GetSSU2IntroKey () const { return m_SSU2Keys ? m_SSU2Keys->intro : nullptr; };
			i2p::crypto::X25519Keys& GetSSU2StaticKeys ();

			uint32_t GetUptime () const; // in seconds
			uint64_t GetLastUpdateTime () const { return m_LastUpdateTime; };
			uint64_t GetBandwidthLimit () const { return m_BandwidthLimit; };
			uint64_t GetTransitBandwidthLimit () const { return (m_BandwidthLimit*m_ShareRatio)/100LL; };
			bool GetTesting () const { return m_Testing; };
			void SetTesting (bool testing);
			RouterStatus GetStatus () const { return m_Status; };
			void SetStatus (RouterStatus status);
			RouterError GetError () const { return m_Error; };
			void SetError (RouterError error) { m_Error = error; };
			bool GetTestingV6 () const { return m_TestingV6; };
			void SetTestingV6 (bool testing);
			RouterStatus GetStatusV6 () const { return m_StatusV6; };
			void SetStatusV6 (RouterStatus status);
			RouterError GetErrorV6 () const { return m_ErrorV6; };
			void SetErrorV6 (RouterError error) { m_ErrorV6 = error; };
			int GetNetID () const { return m_NetID; };
			void SetNetID (int netID) { m_NetID = netID; };
			bool DecryptTunnelBuildRecord (const uint8_t * encrypted, uint8_t * data);
			bool DecryptTunnelShortRequestRecord (const uint8_t * encrypted, uint8_t * data);
			void SubmitECIESx25519Key (const uint8_t * key, uint64_t tag);

			void UpdatePort (int port); // called from Daemon
			void UpdateAddress (const boost::asio::ip::address& host); // called from SSU2 or Daemon
			void PublishNTCP2Address (int port, bool publish, bool v4, bool v6, bool ygg);
			void PublishSSU2Address (int port, bool publish, bool v4, bool v6);
			bool AddSSU2Introducer (const i2p::data::RouterInfo::Introducer& introducer, bool v4);
			void RemoveSSU2Introducer (const i2p::data::IdentHash& h, bool v4);
			void UpdateSSU2Introducer (const i2p::data::IdentHash& h, bool v4, uint32_t iTag, uint32_t iExp);
			void ClearSSU2Introducers (bool v4);
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
			int GetCongestionLevel (bool longTerm) const;
			bool SupportsV6 () const { return m_RouterInfo.IsV6 (); };
			bool SupportsV4 () const { return m_RouterInfo.IsV4 (); };
			bool SupportsMesh () const { return m_RouterInfo.IsMesh (); };
			void SetSupportsV6 (bool supportsV6);
			void SetSupportsV4 (bool supportsV4);
			void SetSupportsMesh (bool supportsmesh, const boost::asio::ip::address_v6& host);
			void SetMTU (int mtu, bool v4);
			void SetHidden(bool hide) { m_IsHiddenMode = hide; };
			bool IsHidden() const { return m_IsHiddenMode; };
			bool IsLimitedConnectivity () const { return m_Status == eRouterStatusProxy; }; // TODO: implement other cases
			i2p::crypto::NoiseSymmetricState& GetCurrentNoiseState () { return m_CurrentNoiseState; };

			void UpdateNTCP2V6Address (const boost::asio::ip::address& host); // called from Daemon. TODO: remove
			void UpdateStats ();
			void UpdateTimestamp (uint64_t ts); // in seconds, called from NetDb before publishing

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
			void NewSSU2Keys ();
			void UpdateNTCP2Keys ();
			void UpdateSSU2Keys ();
			bool Load ();
			void SaveKeys ();
			uint16_t SelectRandomPort () const;
			void PublishNTCP2Address (std::shared_ptr<i2p::data::RouterInfo::Address> address, int port, bool publish) const;

			bool DecryptECIESTunnelBuildRecord (const uint8_t * encrypted, uint8_t * data, size_t clearTextSize);
			void PostGarlicMessage (std::shared_ptr<I2NPMessage> msg);
			void PostDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg);

			void ScheduleInitialPublish ();
			void HandleInitialPublishTimer (const boost::system::error_code& ecode);
			void SchedulePublish ();
			void HandlePublishTimer (const boost::system::error_code& ecode);
			void Publish ();
			void SchedulePublishResend ();
			void HandlePublishResendTimer (const boost::system::error_code& ecode);
			void ScheduleCongestionUpdate ();
			void HandleCongestionUpdateTimer (const boost::system::error_code& ecode);
			void UpdateCongestion ();
			void ScheduleCleanupTimer ();
			void HandleCleanupTimer (const boost::system::error_code& ecode);
			
		private:

			i2p::data::LocalRouterInfo m_RouterInfo;
			i2p::data::PrivateKeys m_Keys;
			std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> m_Decryptor, m_TunnelDecryptor;
			std::shared_ptr<i2p::garlic::RouterIncomingRatchetSession> m_ECIESSession;
			uint64_t m_LastUpdateTime; // in seconds
			bool m_AcceptsTunnels, m_IsFloodfill;
			uint64_t m_StartupTime; // monotonic seconds
			uint64_t m_BandwidthLimit; // allowed bandwidth
			int m_ShareRatio;
			RouterStatus m_Status, m_StatusV6;
			RouterError m_Error, m_ErrorV6;
			bool m_Testing, m_TestingV6;
			int m_NetID;
			std::unique_ptr<NTCP2PrivateKeys> m_NTCP2Keys;
			std::unique_ptr<SSU2PrivateKeys> m_SSU2Keys;
			std::unique_ptr<i2p::crypto::X25519Keys> m_NTCP2StaticKeys, m_SSU2StaticKeys;
			// for ECIESx25519
			i2p::crypto::NoiseSymmetricState m_InitialNoiseState, m_CurrentNoiseState;
			// publish
			std::unique_ptr<RouterService> m_Service;
			std::unique_ptr<boost::asio::deadline_timer> m_PublishTimer, m_CongestionUpdateTimer, m_CleanupTimer;
			std::unordered_set<i2p::data::IdentHash> m_PublishExcluded;
			uint32_t m_PublishReplyToken;
			bool m_IsHiddenMode; // not publish
			mutable std::mutex m_RouterInfoMutex;
	};

	extern RouterContext context;
}

#endif
