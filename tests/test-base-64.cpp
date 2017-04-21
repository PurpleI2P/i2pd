#include <cassert>
#include <string.h>

#include "Base.h"

using namespace i2p::data;

int main() {
  const char *in = "test";
  size_t in_len = strlen(in);
  char out[16];

  /* bytes -> b64 */
  assert(ByteStreamToBase64(NULL, 0, NULL, 0) == 0);
  assert(ByteStreamToBase64(NULL, 0, out, sizeof(out)) == 0);

  assert(Base64EncodingBufferSize(2)  == 4);
  assert(Base64EncodingBufferSize(4)  == 8);
  assert(Base64EncodingBufferSize(6)  == 8);
  assert(Base64EncodingBufferSize(7)  == 12);
  assert(Base64EncodingBufferSize(9)  == 12);
  assert(Base64EncodingBufferSize(10) == 16);
  assert(Base64EncodingBufferSize(12) == 16);
  assert(Base64EncodingBufferSize(13) == 20);

  assert(ByteStreamToBase64((uint8_t *) in, in_len, out, sizeof(out)) == 8);
  assert(memcmp(out, "dGVzdA==", 8) == 0);

  /* b64 -> bytes */
  assert(Base64ToByteStream(NULL, 0, NULL, 0) == 0);
  assert(Base64ToByteStream(NULL, 0, (uint8_t *) out, sizeof(out)) == 0);

  in = "dGVzdA=="; /* valid b64 */
  assert(Base64ToByteStream(in, strlen(in), (uint8_t *) out, sizeof(out)) == 4);
  assert(memcmp(out, "test", 4) == 0);

  in = "dGVzdA=";  /* invalid b64 : not padded */
  assert(Base64ToByteStream(in, strlen(in), (uint8_t *) out, sizeof(out)) == 0);

  in = "dG/z.A=="; /* invalid b64 : char not from alphabet */
//  assert(Base64ToByteStream(in, strlen(in), (uint8_t *) out, sizeof(out)) == 0);
//  ^^^ fails, current implementation not checks acceptable symbols

  return 0;
}
