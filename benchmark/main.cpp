#include "crypto/Signature.h"
#include <cryptopp/osrng.h>
#include <iostream>
#include <chrono>
#include <functional>

typedef std::function<void(CryptoPP::RandomNumberGenerator&, uint8_t*, uint8_t*)> KeyGenerator;

template<class Verifier, class Signer>
void benchmark(std::size_t count, std::size_t public_key_size, std::size_t private_key_size,
    std::size_t signature_size, KeyGenerator generator)
{
    typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimePoint;
    CryptoPP::AutoSeededRandomPool rng;

    uint8_t private_key[private_key_size] = {};
    uint8_t public_key[public_key_size] = {};

    generator(rng, private_key, public_key);

    Verifier verifier(public_key); 
    Signer signer(private_key); 

    uint8_t message[512] = {};
    uint8_t output[signature_size] = {};

    std::chrono::nanoseconds sign_duration(0);
    std::chrono::nanoseconds verify_duration(0);

    for(std::size_t i = 0; i < count; ++i) {
        rng.GenerateBlock(message, 512); 
        TimePoint begin1 = std::chrono::high_resolution_clock::now();
        signer.Sign(rng, message, 512, output);
        TimePoint end1 = std::chrono::high_resolution_clock::now();

        sign_duration += std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - begin1);

        TimePoint begin2 = std::chrono::high_resolution_clock::now();
        verifier.Verify(message, 512, output);
        TimePoint end2 = std::chrono::high_resolution_clock::now();

        verify_duration += std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - begin2);
    }
    std::cout << "Conducted " << count << " experiments." << std::endl;
    std::cout << "Total sign time: " << std::chrono::duration_cast<std::chrono::milliseconds>(sign_duration).count() << std::endl;
    std::cout << "Total verify time: " << std::chrono::duration_cast<std::chrono::milliseconds>(verify_duration).count() << std::endl;
}


int main()
{
    using namespace i2p::crypto;
    std::cout << "--------DSA---------" << std::endl;
    benchmark<DSAVerifier, DSASigner>(
        1000, DSA_PUBLIC_KEY_LENGTH,
        DSA_PRIVATE_KEY_LENGTH, DSA_SIGNATURE_LENGTH,
        &CreateDSARandomKeys
    );
    std::cout << "-----ECDSAP256------" << std::endl;
    benchmark<ECDSAP256Verifier, ECDSAP256Signer>(
        1000, ECDSAP256_KEY_LENGTH,
        ECDSAP256_KEY_LENGTH, 64,
        &CreateECDSAP256RandomKeys
    );
    std::cout << "-----ECDSAP384------" << std::endl;
    benchmark<ECDSAP384Verifier, ECDSAP384Signer>(
        1000, ECDSAP384_KEY_LENGTH,
        ECDSAP384_KEY_LENGTH, 64,
        &CreateECDSAP384RandomKeys
    );
    std::cout << "-----ECDSAP521------" << std::endl;
    benchmark<ECDSAP521Verifier, ECDSAP521Signer>(
        1000, ECDSAP521_KEY_LENGTH,
        ECDSAP521_KEY_LENGTH, 64,
        &CreateECDSAP521RandomKeys
    );
    std::cout << "-----EDDSA25519-----" << std::endl;
    benchmark<EDDSA25519Verifier, EDDSA25519Signer>(
        1000, EDDSA25519_PUBLIC_KEY_LENGTH,
        EDDSA25519_PRIVATE_KEY_LENGTH, 64,
        &CreateEDDSARandomKeys
    );
}
