#ifndef CRYPTO_H__
#define CRYPTO_H__

#include <inttypes.h>
#include <string>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include "Base.h"

namespace i2p
{
namespace crypto
{
	struct CryptoConstants
	{
		// DH/ElGamal
		BIGNUM * elgp;
		BIGNUM * elgg; 

		// DSA
		BIGNUM * dsap;		
		BIGNUM * dsaq;
		BIGNUM * dsag;

		// RSA
		BIGNUM * rsae;
		
		CryptoConstants (const uint8_t * elgp_, int elgg_, const uint8_t * dsap_, 
			const uint8_t * dsaq_, const uint8_t * dsag_, int rsae_)
		{
			elgp = BN_new ();
			BN_bin2bn (elgp_, 256, elgp);
			elgg = BN_new ();
			BN_set_word (elgg, elgg_);
			dsap = BN_new ();
			BN_bin2bn (dsap_, 128, dsap);
			dsaq = BN_new ();
			BN_bin2bn (dsaq_, 20, dsaq);
			dsag = BN_new ();
			BN_bin2bn (dsag_, 128, dsag);
			rsae = BN_new ();
			BN_set_word (rsae, rsae_);
		}
		
		~CryptoConstants ()
		{
			BN_free (elgp);  BN_free (elgg); BN_free (dsap); BN_free (dsaq); BN_free (dsag); BN_free (rsae);
		}	
	};	
	
	const CryptoConstants& GetCryptoConstants ();
	
	// DH/ElGamal	
	#define elgp GetCryptoConstants ().elgp
	#define elgg GetCryptoConstants ().elgg

	// DSA
	#define dsap GetCryptoConstants ().dsap	
	#define dsaq GetCryptoConstants ().dsaq
	#define dsag GetCryptoConstants ().dsag	

	// RSA
	#define rsae GetCryptoConstants ().rsae	

	bool bn2buf (const BIGNUM * bn, uint8_t * buf, size_t len);

	// DH
	class DHKeys
	{
		public:
			
			DHKeys ();
			~DHKeys ();

			void GenerateKeys (uint8_t * priv = nullptr, uint8_t * pub = nullptr);
			const uint8_t * GetPublicKey ();
			void Agree (const uint8_t * pub, uint8_t * shared);
			
		private:

			DH * m_DH;
			uint8_t m_PublicKey[256];
			bool m_IsUpdated;
	};	
	
	// ElGamal
	class ElGamalEncryption
	{
		public:

			ElGamalEncryption (const uint8_t * key);
			~ElGamalEncryption ();
			
			void Encrypt (const uint8_t * data, int len, uint8_t * encrypted, bool zeroPadding = false) const;

		private:

			BN_CTX * ctx;
			BIGNUM * a, * b1;
	};

	bool ElGamalDecrypt (const uint8_t * key, const uint8_t * encrypted, uint8_t * data, bool zeroPadding = false);
	void GenerateElGamalKeyPair (uint8_t * priv, uint8_t * pub);

	// HMAC
	typedef i2p::data::Tag<32> MACKey;		
	void HMACMD5Digest (uint8_t * msg, size_t len, const MACKey& key, uint8_t * digest);

	// AES
	struct ChipherBlock	
	{
		uint8_t buf[16];

		void operator^=(const ChipherBlock& other) // XOR
		{
#if defined(__x86_64__) // for Intel x64 
			__asm__
			(
				"movups	(%[buf]), %%xmm0 \n"	
				"movups	(%[other]), %%xmm1 \n"	
				"pxor %%xmm1, %%xmm0 \n"
				"movups	%%xmm0, (%[buf]) \n"
				: 
				: [buf]"r"(buf), [other]"r"(other.buf) 
				: "%xmm0", "%xmm1", "memory"
			);			
#else
			// TODO: implement it better
			for (int i = 0; i < 16; i++)
				buf[i] ^= other.buf[i];
#endif
		}	 
	};

	typedef i2p::data::Tag<32> AESKey;
	
	template<size_t sz>
	class AESAlignedBuffer // 16 bytes alignment
	{
		public:
		
			AESAlignedBuffer ()
			{
				m_Buf = m_UnalignedBuffer;
				uint8_t rem = ((size_t)m_Buf) & 0x0f;
				if (rem)
					m_Buf += (16 - rem);
			}
		
			operator uint8_t * () { return m_Buf; };
			operator const uint8_t * () const { return m_Buf; };

		private:

			uint8_t m_UnalignedBuffer[sz + 15]; // up to 15 bytes alignment
			uint8_t * m_Buf;
	};			


#ifdef AESNI
	class ECBCryptoAESNI
	{	
		public:

			uint8_t * GetKeySchedule () { return m_KeySchedule; };

		protected:

			void ExpandKey (const AESKey& key);
		
		private:

			AESAlignedBuffer<240> m_KeySchedule;  // 14 rounds for AES-256, 240 bytes
	};	

	class ECBEncryptionAESNI: public ECBCryptoAESNI
	{
		public:
		
			void SetKey (const AESKey& key) { ExpandKey (key); };
			void Encrypt (const ChipherBlock * in, ChipherBlock * out);	
	};	

	class ECBDecryptionAESNI: public ECBCryptoAESNI
	{
		public:
		
			void SetKey (const AESKey& key);
			void Decrypt (const ChipherBlock * in, ChipherBlock * out);		
	};	

	typedef ECBEncryptionAESNI ECBEncryption;
	typedef ECBDecryptionAESNI ECBDecryption;

#else // use openssl

	class ECBEncryption
	{
		public:
		
			void SetKey (const AESKey& key) 
			{ 
				AES_set_encrypt_key (key, 256, &m_Key);
			}
			void Encrypt (const ChipherBlock * in, ChipherBlock * out)
			{
				AES_encrypt (in->buf, out->buf, &m_Key);
			}	

		private:

			AES_KEY m_Key;
	};	

	class ECBDecryption
	{
		public:
		
			void SetKey (const AESKey& key) 
			{ 
				AES_set_decrypt_key (key, 256, &m_Key); 
			}
			void Decrypt (const ChipherBlock * in, ChipherBlock * out)
			{
				AES_decrypt (in->buf, out->buf, &m_Key);
			}	

		private:

			AES_KEY m_Key;
	};		


#endif			

	class CBCEncryption
	{
		public:
	
			CBCEncryption () { memset (m_LastBlock.buf, 0, 16); };

			void SetKey (const AESKey& key) { m_ECBEncryption.SetKey (key); }; // 32 bytes
			void SetIV (const uint8_t * iv) { memcpy (m_LastBlock.buf, iv, 16); }; // 16 bytes

			void Encrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out);
			void Encrypt (const uint8_t * in, std::size_t len, uint8_t * out);
			void Encrypt (const uint8_t * in, uint8_t * out); // one block

		private:

			ChipherBlock m_LastBlock;
			
			ECBEncryption m_ECBEncryption;
	};

	class CBCDecryption
	{
		public:
	
			CBCDecryption () { memset (m_IV.buf, 0, 16); };

			void SetKey (const AESKey& key) { m_ECBDecryption.SetKey (key); }; // 32 bytes
			void SetIV (const uint8_t * iv) { memcpy (m_IV.buf, iv, 16); }; // 16 bytes

			void Decrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out);
			void Decrypt (const uint8_t * in, std::size_t len, uint8_t * out);
			void Decrypt (const uint8_t * in, uint8_t * out); // one block

		private:

			ChipherBlock m_IV;
			ECBDecryption m_ECBDecryption;
	};	

	class TunnelEncryption // with double IV encryption
	{
		public:

			void SetKeys (const AESKey& layerKey, const AESKey& ivKey)
			{
				m_LayerEncryption.SetKey (layerKey);
				m_IVEncryption.SetKey (ivKey);
			}	

			void Encrypt (const uint8_t * in, uint8_t * out); // 1024 bytes (16 IV + 1008 data)		

		private:

			ECBEncryption m_IVEncryption;
#ifdef AESNI
			ECBEncryption m_LayerEncryption;
#else
			CBCEncryption m_LayerEncryption;
#endif
	};

	class TunnelDecryption // with double IV encryption
	{
		public:

			void SetKeys (const AESKey& layerKey, const AESKey& ivKey)
			{
				m_LayerDecryption.SetKey (layerKey);
				m_IVDecryption.SetKey (ivKey);
			}			

			void Decrypt (const uint8_t * in, uint8_t * out); // 1024 bytes (16 IV + 1008 data)	

		private:

			ECBDecryption m_IVDecryption;
#ifdef AESNI
			ECBDecryption m_LayerDecryption;
#else
			CBCDecryption m_LayerDecryption;
#endif
	};	
}		
}	

#endif
