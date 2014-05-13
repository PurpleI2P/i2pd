#ifndef AES_H__
#define AES_H__

#include <inttypes.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

namespace i2p
{
namespace crypto
{	
	union ChipherBlock	
	{
		uint8_t buf[16];
		uint64_t ll[2];

		void operator^=(const ChipherBlock& other) // XOR
		{
			ll[0] ^= other.ll[0];
			ll[1] ^= other.ll[1];
		}	 
	};

#ifdef __x86_64__
	// AES-NI assumed
	class ECBCryptoAESNI
	{	
		public:

			ECBCryptoAESNI ();
			uint8_t * GetKeySchedule () { return m_KeySchedule; };
			
		protected:

			void ExpandKey (const uint8_t * key);
		
		protected:

			uint8_t * m_KeySchedule; // start of 16 bytes boundary of m_UnalignedBuffer
			uint8_t m_UnalignedBuffer[256]; // 14 rounds for AES-256, 240 + 16 bytes
	};	

	class ECBEncryptionAESNI: public ECBCryptoAESNI
	{
		public:
		
			void SetKey (const uint8_t * key) { ExpandKey (key); };
			void Encrypt (const ChipherBlock * in, ChipherBlock * out);	
	};	

	class ECBDecryptionAESNI: public ECBCryptoAESNI
	{
		public:
		
			void SetKey (const uint8_t * key);
			void Decrypt (const ChipherBlock * in, ChipherBlock * out);		
	};	

	typedef ECBEncryptionAESNI ECBEncryption;
	typedef ECBDecryptionAESNI ECBDecryption;

#else // use crypto++

	class ECBEncryption
	{
		public:
		
			void SetKey (const uint8_t * key) 
			{ 
				m_Encryption.SetKey (key, 32); 
			}
			void Encrypt (const ChipherBlock * in, ChipherBlock * out)
			{
				m_Encryption.ProcessData (out->buf, in->buf, 16);
			}	

		private:

			CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_Encryption;
	};	

	class ECBDecryption
	{
		public:
		
			void SetKey (const uint8_t * key) 
			{ 
				m_Decryption.SetKey (key, 32); 
			}
			void Decrypt (const ChipherBlock * in, ChipherBlock * out)
			{
				m_Decryption.ProcessData (out->buf, in->buf, 16);
			}	

		private:

			CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption m_Decryption;
	};		


#endif			

	class CBCEncryption
	{
		public:
	
			CBCEncryption () { memset (m_LastBlock.buf, 0, 16); };

			void SetKey (const uint8_t * key) { m_ECBEncryption.SetKey (key); }; // 32 bytes
			void SetIV (const uint8_t * iv) { memcpy (m_LastBlock.buf, iv, 16); }; // 16 bytes

			void Encrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out);
			bool Encrypt (const uint8_t * in, std::size_t len, uint8_t * out);

		private:

			ChipherBlock m_LastBlock;
			
			ECBEncryption m_ECBEncryption;
	};

	class CBCDecryption
	{
		public:
	
			CBCDecryption () { memset (m_IV.buf, 0, 16); };

			void SetKey (const uint8_t * key) { m_ECBDecryption.SetKey (key); }; // 32 bytes
			void SetIV (const uint8_t * iv) { memcpy (m_IV.buf, iv, 16); }; // 16 bytes

			void Decrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out);
			bool Decrypt (const uint8_t * in, std::size_t len, uint8_t * out);

		private:

			ChipherBlock m_IV;
			ECBDecryption m_ECBDecryption;
	};	
}
}

#endif

