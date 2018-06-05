#include <openssl/rand.h>
#include "Crypto.h"
#include "Ed25519.h"
#include "ChaCha20.h"
#include "Poly1305.h"
#include "NTCP2.h"

namespace i2p
{
namespace transport
{
	NTCP2Session::NTCP2Session (std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter):
		TransportSession (in_RemoteRouter, 30)
	{
	}

	NTCP2Session::~NTCP2Session ()
	{
	}

	void NTCP2Session::CreateEphemeralKey (uint8_t * pub)
	{
		uint8_t key[32];
		RAND_bytes (key, 32);
		i2p::crypto::Ed25519::ExpandPrivateKey (key, m_ExpandedPrivateKey);
		BN_CTX * ctx = BN_CTX_new ();
		auto publicKey = i2p::crypto::GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, ctx);
		i2p::crypto::GetEd25519 ()->EncodePublicKey (publicKey, pub, ctx);
		BN_CTX_free (ctx);
	}

	void NTCP2Session::SendSessionRequest (const uint8_t * iv)
	{
		i2p::crypto::AESAlignedBuffer<32> x;
		CreateEphemeralKey (x);
		// encrypt X
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (GetRemoteIdentity ()->GetIdentHash ());
		encryption.SetIV (iv);
		encryption.Encrypt (2, x.GetChipherBlock (), x.GetChipherBlock ());		
	}	
}
}

