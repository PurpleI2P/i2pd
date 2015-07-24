#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>
#include "../Identity.h"

BOOST_AUTO_TEST_SUITE(DataTests)

using namespace i2p::data;

BOOST_AUTO_TEST_CASE(Base64EncodeEmpty)
{
    BOOST_CHECK_EQUAL(ByteStreamToBase64(nullptr, 0, nullptr, 0), 0);
}

BOOST_AUTO_TEST_CASE(Base64DecodeEmpty)
{
    BOOST_CHECK_EQUAL(Base64ToByteStream(nullptr, 0, nullptr, 0), 0);
}

BOOST_AUTO_TEST_CASE(Base64Encode)
{
    const uint8_t input[] = {
        0x53, 0xd3, 0x60, 0xfa, 0xf9, 0x58, 0xd0, 0x5e, 0x41, 0xa9, 0x6c,
        0xf1, 0x9f, 0xc4, 0xe, 0x23, 0x9b, 0xca, 0xb1, 0x61, 0xa7, 0x33, 0xcf,
        0x1f, 0x30
    };
    const char* output = "U9Ng-vlY0F5BqWzxn8QOI5vKsWGnM88fMA==";
    char result[36];
    const size_t size = ByteStreamToBase64(input, 25, result, 36);

    BOOST_CHECK_EQUAL_COLLECTIONS(result, result + 36, output, output + 36);
    BOOST_CHECK_EQUAL(size, 36);
}

BOOST_AUTO_TEST_CASE(Base64Decode)
{
    const char* input = "U9Ng-vlY0F5BqWzxn8QOI5vKsWGnM88fMA==";
    const uint8_t output[] = {
        0x53, 0xd3, 0x60, 0xfa, 0xf9, 0x58, 0xd0, 0x5e, 0x41, 0xa9, 0x6c,
        0xf1, 0x9f, 0xc4, 0xe, 0x23, 0x9b, 0xca, 0xb1, 0x61, 0xa7, 0x33, 0xcf,
        0x1f, 0x30
    };
    uint8_t result[25];
    const size_t size = Base64ToByteStream(input, 36, result, 25);

    BOOST_CHECK_EQUAL_COLLECTIONS(result, result + 25, output, output + 25);
    BOOST_CHECK_EQUAL(size, 25);
}

BOOST_AUTO_TEST_CASE(Base64EncodeBufferTooSmall)
{
    const uint8_t input[] = {0x53, 0xd3};
    char result[3];
    BOOST_CHECK_EQUAL(ByteStreamToBase64(input, 2, result, 3), 0);
}

BOOST_AUTO_TEST_CASE(Base64DecodeBufferTooSmall)
{
    const char* input = "U9M=";
    uint8_t result[1];
    BOOST_CHECK_EQUAL(Base64ToByteStream(input, 4, result, 1), 0);
}

BOOST_AUTO_TEST_CASE(Base32EncodeEmpty)
{
    BOOST_CHECK_EQUAL(ByteStreamToBase32(nullptr, 0, nullptr, 0), 0);
}

BOOST_AUTO_TEST_CASE(Base32DecodeEmpty)
{
    BOOST_CHECK_EQUAL(Base32ToByteStream(nullptr, 0, nullptr, 0), 0);
}

BOOST_AUTO_TEST_CASE(Base32Encode)
{
    const uint8_t input[] = {
        0x53, 0xd3, 0x60, 0xfa, 0xf9, 0x58, 0xd0, 0x5e, 0x41, 0xa9, 0x6c,
        0xf1, 0x9f, 0xc4, 0xe, 0x23, 0x9b, 0xca, 0xb1, 0x61, 0xa7, 0x33, 0xcf,
        0x1f, 0x30
    };
    const char* output = "kpjwb6xzldif4qnjntyz7raoeon4vmlbu4z46hzq";
    char result[40];
    const size_t size = ByteStreamToBase32(input, 25, result, 40);

    BOOST_CHECK_EQUAL_COLLECTIONS(result, result + 40, output, output + 40);
    BOOST_CHECK_EQUAL(size, 40);
}

BOOST_AUTO_TEST_CASE(Base32Decode)
{
    const char* input = "kpjwb6xzldif4qnjntyz7raoeon4vmlbu4z46hzq";
    const uint8_t output[] = {
        0x53, 0xd3, 0x60, 0xfa, 0xf9, 0x58, 0xd0, 0x5e, 0x41, 0xa9, 0x6c,
        0xf1, 0x9f, 0xc4, 0xe, 0x23, 0x9b, 0xca, 0xb1, 0x61, 0xa7, 0x33, 0xcf,
        0x1f, 0x30
    };
    uint8_t result[25];
    const size_t size = Base32ToByteStream(input, 40, result, 25);
    BOOST_CHECK_EQUAL_COLLECTIONS(result, result + 25, output, output + 25);
    BOOST_CHECK_EQUAL(size, 25);
}

BOOST_AUTO_TEST_CASE(Base32EncodeBufferTooSmall)
{
    const uint8_t input[] = {0x53, 0xd3};
    char result[3];
    BOOST_CHECK_EQUAL(ByteStreamToBase64(input, 2, result, 3), 0);
}

BOOST_AUTO_TEST_CASE(Base32DecodeBufferTooSmall)
{
    const char* input = "kpjq";
    uint8_t result[1];
    BOOST_CHECK_EQUAL(Base64ToByteStream(input, 4, result, 1), 0);
}

BOOST_AUTO_TEST_SUITE_END()
