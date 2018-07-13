#ifndef NTCP2_H__
#define NTCP2_H__

#include <inttypes.h>
#include <memory>
#include <thread>
#include <openssl/bn.h>
#include <boost/asio.hpp>
#include "RouterInfo.h"
#include "TransportSession.h"

namespace i2p
{
namespace transport
{
	struct NTCP2Establisher
	{
		NTCP2Establisher ();
		~NTCP2Establisher ();
		
		const uint8_t * GetPub () const { return m_EphemeralPublicKey; };
		const uint8_t * GetPriv () const { return m_EphemeralPrivateKey; };
		const uint8_t * GetRemotePub () const { return m_RemoteEphemeralPublicKey; }; // Y for Alice and X for Bob
		uint8_t * GetRemotePub () { return m_RemoteEphemeralPublicKey; }; // to set

		const uint8_t * GetK () const { return m_K; };
		const uint8_t * GetCK () const { return m_CK; };
		const uint8_t * GetH () const { return m_H; };

		void KDF1Alice ();
		void KDF1Bob ();

		void MixKey (const uint8_t * inputKeyMaterial, uint8_t * derived);
		void KeyDerivationFunction1 (const uint8_t * rs, const uint8_t * priv, const uint8_t * pub); // for SessionRequest
		void KeyDerivationFunction2 (const uint8_t * sessionRequest, size_t sessionRequestLen); // for SessionCreate
		void KDF3Alice (); // for SessionConfirmed part 2
		void KDF3Bob ();
		void CreateEphemeralKey ();


		BN_CTX * m_Ctx;
		uint8_t m_EphemeralPrivateKey[32], m_EphemeralPublicKey[32], m_RemoteEphemeralPublicKey[32]; // x25519
		uint8_t m_RemoteStaticKey[32], m_IV[16], m_H[32] /*h*/, m_CK[33] /*ck*/, m_K[32] /*k*/;
		uint16_t m3p2Len; 
	};		

	class NTCP2Server;
	class NTCP2Session: public TransportSession, public std::enable_shared_from_this<NTCP2Session>
	{
		public:

			NTCP2Session (NTCP2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr); 
			~NTCP2Session ();
			void Terminate ();
			void Done ();

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };

			void ClientLogin (); // Alice 
			void ServerLogin (); // Bob
			void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) {}; // TODO

		private:

			void Established ();

			void CreateNonce (uint64_t seqn, uint8_t * nonce);
			void KeyDerivationFunctionDataPhase ();

			// establish
			void SendSessionRequest ();
			void SendSessionCreated ();
			void SendSessionConfirmed ();

			void HandleSessionRequestSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleSessionRequestReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleSessionRequestPaddingReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleSessionCreatedSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleSessionCreatedReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleSessionCreatedPaddingReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleSessionConfirmedSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleSessionConfirmedReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);

			// data
			void ReceiveLength ();
			void HandleReceivedLength (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void ProcessNextFrame (const uint8_t * frame, size_t len);

			void SendNextFrame (const uint8_t * payload, size_t len); 
			void HandleNextFrameSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);

		private:

			NTCP2Server& m_Server;
			boost::asio::ip::tcp::socket m_Socket;
			bool m_IsEstablished, m_IsTerminated;

			std::unique_ptr<NTCP2Establisher> m_Establisher;
			uint8_t * m_SessionRequestBuffer, * m_SessionCreatedBuffer, * m_SessionConfirmedBuffer;
			size_t m_SessionRequestBufferLen, m_SessionCreatedBufferLen;
			// data phase
			uint8_t m_Kab[33], m_Kba[32], m_Sipkeysab[33], m_Sipkeysba[32]; 
			const uint8_t * m_SendKey, * m_ReceiveKey, * m_SendSipKey, * m_ReceiveSipKey;
			uint16_t m_NextReceivedLen; 
			uint8_t * m_NextReceivedBuffer, * m_NextSendBuffer;
			uint8_t m_ReceiveIV[8], m_SendIV[8];
			uint64_t m_ReceiveSequenceNumber, m_SendSequenceNumber;
	};

	class NTCP2Server
	{
		public:

			NTCP2Server ();
			~NTCP2Server ();

			void Start ();
			void Stop ();

			boost::asio::io_service& GetService () { return m_Service; };
		
			void Connect(const boost::asio::ip::address & address, uint16_t port, std::shared_ptr<NTCP2Session> conn);

		private:

			void Run ();
			void HandleConnect (const boost::system::error_code& ecode, std::shared_ptr<NTCP2Session> conn);		

		private:

			bool m_IsRunning;
			std::thread * m_Thread;
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
	};
}
}

#endif
