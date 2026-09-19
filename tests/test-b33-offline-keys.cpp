#include <cassert>
#include <memory>
#include <string.h>
#include <vector>
#include "Blinding.h"
#include "I2PEndian.h"
#include "Identity.h"
#include "Timestamp.h"

using namespace i2p::data;
using namespace i2p::util;
using namespace i2p::crypto;

const size_t TEST_DATA_LENGTH = 100;
const int TEST_NUM_DAYS = 3;

// the layout i2pd-tools writes: version || ident hash || number of keys, then a key per day
static std::vector<uint8_t> CreateB33OfflineKeys (const PrivateKeys& keys, int days, uint64_t firstMidnight)
{
	BlindedPublicKey blindedKey (keys.GetPublic ());
	std::unique_ptr<Verifier> transientVerifier (IdentityEx::CreateVerifier (SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519));
	std::unique_ptr<Verifier> blindedVerifier (IdentityEx::CreateVerifier (blindedKey.GetBlindedSigType ()));
	assert (transientVerifier && blindedVerifier);
	const size_t signedLen = OFFLINE_SIGNATURE_HEADER_LENGTH + transientVerifier->GetPublicKeyLen ();
	const size_t keyLen = signedLen + blindedVerifier->GetSignatureLen () + transientVerifier->GetPrivateKeyLen ();
	std::vector<uint8_t> buf (B33_OFFLINE_KEYS_HEADER_LENGTH + days*keyLen);
	size_t offset = 0;
	buf[offset] = B33_OFFLINE_KEYS_VERSION; offset++;
	memcpy (buf.data () + offset, keys.GetPublic ()->GetIdentHash (), IdentHash::len); offset += IdentHash::len;
	htobe16buf (buf.data () + offset, days); offset += 2;
	for (int i = 0; i < days; i++)
	{
		char date[9];
		GetDateString (firstMidnight + i*SECONDS_PER_DAY, date);
		uint8_t * signedData = buf.data () + offset;
		htobe32buf (signedData, firstMidnight + (i + 1)*SECONDS_PER_DAY); // expires at the end of that day
		htobe16buf (signedData + 4, SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519);
		uint8_t blindedPriv[EDDSA25519_PRIVATE_KEY_LENGTH], blindedPub[EDDSA25519_PUBLIC_KEY_LENGTH];
		const size_t blindedKeyLen = blindedKey.BlindPrivateKey (keys.GetSigningPrivateKey (), date, blindedPriv, blindedPub);
		assert (blindedKeyLen); (void)blindedKeyLen;
		std::unique_ptr<Signer> blindedSigner (PrivateKeys::CreateSigner (blindedKey.GetBlindedSigType (), blindedPriv));
		assert (blindedSigner);
		PrivateKeys::GenerateSigningKeyPair (SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519,
			signedData + signedLen + blindedVerifier->GetSignatureLen (), signedData + OFFLINE_SIGNATURE_HEADER_LENGTH);
		blindedSigner->Sign (signedData, signedLen, signedData + signedLen);
		offset += keyLen;
	}
	return buf;
}

static void BlindedSignerTest ()
{
	auto keys = PrivateKeys::CreateRandomKeys (SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
	auto blindedKeys = BlindedPrivateKey::Create (keys);
	assert (blindedKeys);
	auto timestamp = GetSecondsSinceEpoch ();
	auto signer = blindedKeys->CreateSigner (timestamp);
	assert (signer);
	assert (signer->GetOfflineSignature ().empty ()); // the destination blinds its own key
	char date[9];
	GetDateString (timestamp, date);
	uint8_t blindedPub[EDDSA25519_PUBLIC_KEY_LENGTH];
	const size_t publicKeyLen = blindedKeys->GetPublic ().GetBlindedKey (date, blindedPub);
	assert (publicKeyLen == signer->GetBlindedPublicKeyLen ()); (void)publicKeyLen;
	assert (!memcmp (blindedPub, signer->GetBlindedPublicKey (), publicKeyLen));
	assert (blindedKeys->GetStoreHash (timestamp) == blindedKeys->GetPublic ().GetStoreHash (date));
	// the outer layer is verified with the blinded key of that day
	uint8_t buf[TEST_DATA_LENGTH], signature[EDDSA25519_SIGNATURE_LENGTH];
	memset (buf, 1, TEST_DATA_LENGTH);
	signer->Sign (buf, TEST_DATA_LENGTH, signature);
	std::unique_ptr<Verifier> blindedVerifier (IdentityEx::CreateVerifier (blindedKeys->GetPublic ().GetBlindedSigType ()));
	blindedVerifier->SetPublicKey (blindedPub);
	assert (blindedVerifier->Verify (buf, TEST_DATA_LENGTH, signature));
}

static void OfflineSignerTest ()
{
	auto keys = PrivateKeys::CreateRandomKeys (SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
	auto offlineKeys = keys.CreateOfflineKeys (SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
		GetSecondsSinceEpoch () + SECONDS_PER_DAY);
	assert (offlineKeys.IsOfflineSignature ());
	std::vector<uint8_t> buf (offlineKeys.GetFullLen ());
	const size_t written = offlineKeys.ToBuffer (buf.data (), buf.size ());
	assert (written == buf.size ()); (void)written;
	PrivateKeys keys1;
	const size_t parsed = keys1.FromBuffer (buf.data (), buf.size ());
	assert (parsed == buf.size ()); (void)parsed;
	assert (keys1.IsOfflineSignature ());
	assert (keys1.GetOfflineSignature () == offlineKeys.GetOfflineSignature ());
	assert (keys1.GetSignatureLen () == offlineKeys.GetSignatureLen ());
	// the transient signs, not the destination
	uint8_t data[TEST_DATA_LENGTH], signature[EDDSA25519_SIGNATURE_LENGTH];
	memset (data, 2, TEST_DATA_LENGTH);
	keys1.Sign (data, TEST_DATA_LENGTH, signature);
	assert (!keys1.GetPublic ()->Verify (data, TEST_DATA_LENGTH, signature));
	// an offline destination has no key to blind
	assert (!BlindedPrivateKey::Create (keys1));
}

static void B33OfflineKeysTest ()
{
	auto keys = PrivateKeys::CreateRandomKeys (SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
	const uint64_t midnight = (GetSecondsSinceEpoch ()/SECONDS_PER_DAY)*SECONDS_PER_DAY;
	const uint32_t expires = midnight + TEST_NUM_DAYS*SECONDS_PER_DAY;
	auto b33OfflineKeys = CreateB33OfflineKeys (keys, TEST_NUM_DAYS, midnight);
	auto offlineKeys = keys.CreateOfflineKeys (SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519, expires);
	// the keys file: offline keys followed by the b33 offline keys
	std::vector<uint8_t> buf (offlineKeys.GetFullLen () + b33OfflineKeys.size ());
	size_t l = offlineKeys.ToBuffer (buf.data (), buf.size ());
	assert (l);
	memcpy (buf.data () + l, b33OfflineKeys.data (), b33OfflineKeys.size ());
	PrivateKeys keys1;
	const size_t parsed = keys1.FromBuffer (buf.data (), buf.size ());
	assert (parsed == buf.size ()); (void)parsed;
	assert (keys1.GetB33OfflineKeys ().GetLen () == b33OfflineKeys.size ());
	std::vector<uint8_t> buf1 (keys1.GetFullLen ());
	const size_t written = keys1.ToBuffer (buf1.data (), buf1.size ());
	assert (written == buf.size ()); (void)written;
	assert (buf1 == buf); // the keys file survives a round trip

	auto blindedKeys = BlindedPrivateKey::Create (keys1);
	assert (blindedKeys);
	for (int i = 0; i < TEST_NUM_DAYS; i++)
	{
		uint64_t timestamp = midnight + i*SECONDS_PER_DAY + SECONDS_PER_DAY/2;
		auto signer = blindedKeys->CreateSigner (timestamp);
		assert (signer);
		const auto& offlineSignature = signer->GetOfflineSignature ();
		assert (!offlineSignature.empty ()); // the day's transient is authorized by the blinded key
		char date[9];
		GetDateString (timestamp, date);
		uint8_t blindedPub[EDDSA25519_PUBLIC_KEY_LENGTH];
		const size_t publicKeyLen = blindedKeys->GetPublic ().GetBlindedKey (date, blindedPub);
		assert (!memcmp (blindedPub, signer->GetBlindedPublicKey (), publicKeyLen)); (void)publicKeyLen;
		assert (blindedKeys->GetStoreHash (timestamp) == blindedKeys->GetPublic ().GetStoreHash (date));
		// the outer layer is signed by the transient the offline signature carries
		uint8_t data[TEST_DATA_LENGTH], signature[EDDSA25519_SIGNATURE_LENGTH];
		memset (data, 3, TEST_DATA_LENGTH);
		signer->Sign (data, TEST_DATA_LENGTH, signature);
		std::unique_ptr<Verifier> transientVerifier (IdentityEx::CreateVerifier (SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519));
		transientVerifier->SetPublicKey (offlineSignature.data () + OFFLINE_SIGNATURE_HEADER_LENGTH);
		assert (transientVerifier->Verify (data, TEST_DATA_LENGTH, signature));
	}
	assert (!blindedKeys->CreateSigner (expires)); // nothing to sign with after the last day
	assert (!blindedKeys->CreateSigner (midnight - 1)); // or before the first one
}

int main ()
{
	BlindedSignerTest ();
	OfflineSignerTest ();
	B33OfflineKeysTest ();
}
