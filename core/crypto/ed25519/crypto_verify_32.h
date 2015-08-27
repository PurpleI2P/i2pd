#include <cstring>

#define crypto_verify_32(a,b) (std::memcmp((a), (b), 32) == 0)
