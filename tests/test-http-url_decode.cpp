#include <cassert>
#include "../HTTP.h"

using namespace i2p::http;

int main() {
  std::string in("/%D1%81%D1%82%D1%80%D0%B0%D0%BD%D0%B8%D1%86%D0%B0/");
  std::string out = UrlDecode(in);

  assert(strcmp(out.c_str(), "/страница/") == 0);

  in = "/%00/";
  out = UrlDecode(in, false);
  assert(strcmp(out.c_str(), "/%00/") == 0);
  out = UrlDecode(in, true);
  assert(strcmp(out.c_str(), "/\0/") == 0);

  return 0;
}
