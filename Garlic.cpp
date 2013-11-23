#include <inttypes.h>
#include <map>
#include <string>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include "RouterContext.h"
#include "Timestamp.h"
#include "ElGamal.h"
#include "Garlic.h"

namespace i2p
{
	I2NPMessage * WrapI2NPMessage (const uint8_t * encryptionKey, I2NPMessage * msg)
	{
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		// create ElGamal block
		ElGamalBlock elGamal;
		rnd.GenerateBlock (elGamal.sessionKey, 32); // session key
		rnd.GenerateBlock (elGamal.preIV, 32); // Pre-IV
		uint8_t iv[32]; // IV is first 16 bytes
		CryptoPP::SHA256().CalculateDigest(iv, elGamal.preIV, 32);
		
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
		encryption.SetKeyWithIV (elGamal.sessionKey, 32, iv); 
		
		I2NPMessage * m = NewI2NPMessage ();
		uint8_t * buf = m->GetPayload () + 4; // 4 bytes for length
		i2p::crypto::ElGamalEncrypt (encryptionKey, (uint8_t *)&elGamal, sizeof(elGamal), buf, true);
		buf += 514;
		size_t blockSize = 0;
		*(uint16_t *)buf = 0; // tag count
		blockSize += 2;
		uint32_t * payloadSize = (uint32_t *)(buf + blockSize);
		blockSize += 4;
		uint8_t * payloadHash = buf + blockSize;
		blockSize += 32;
		buf[blockSize] = 0; // flag
		blockSize++;
		size_t len = CreateGarlicPayload (buf + blockSize, msg);
		*payloadSize = htobe32 (len);
		CryptoPP::SHA256().CalculateDigest(payloadHash, buf + blockSize, len);
		blockSize += len;
		size_t rem = blockSize % 16;
		if (rem)
			blockSize += (16-rem); //padding
		encryption.ProcessData(buf, buf, blockSize);

		*(uint32_t *)(m->GetPayload ()) = htobe32 (blockSize + 514);
		m->len += blockSize + 514 + 4;	
		FillI2NPMessageHeader (m, eI2NPGarlic);
		DeleteI2NPMessage (msg);
		return m;
	}	

	size_t CreateGarlicPayload (uint8_t * payload, I2NPMessage * msg)
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();
		size_t size = 0;
		payload[size] = 1; // 1 clove
		size++;
		payload[size] = 0;//  delivery instructions flag
		size++;
		memcpy (payload + size, msg->GetBuffer (), msg->GetLength ());
		size += msg->GetLength ();
		*(uint32_t *)(payload + size) = htobe32 (1011); // CloveID
		size += 4;
		*(uint64_t *)(payload + size) = htobe64 (ts); // Expiration of clove
		size += 8;
		memset (payload + size, 0, 3); // certificate of clove
		size += 3;
		memset (payload + size, 0, 3); // certificate of message
		size += 3;
		*(uint32_t *)(payload + size) = htobe32 (2022); // MessageID
		size += 4;
		*(uint64_t *)(payload + size) = htobe64 (ts); // Expiration of message
		size += 8;
		return size;
	}	
}	