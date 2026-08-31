#include <cassert>
#include "HTTP.h"

using namespace i2p::http;

int main() {
  const char *buf =
    "4\r\n"
    "HTTP\r\n"
    "A\r\n"
    " response \r\n"
    "E\r\n"
    "with \r\n"
    "chunks.\r\n"
    "0\r\n"
    "\r\n"
    ;
  std::stringstream in(buf);
  std::stringstream out;

  assert(MergeChunkedResponse(in, out) == true);
  assert(out.str() == "HTTP response with \r\nchunks.");

  /* a chunk that promises more bytes than the response carries */
  std::stringstream truncated("20\r\nshort\r\n");
  std::stringstream out2;

  assert(MergeChunkedResponse(truncated, out2) == false);

  return 0;
}
