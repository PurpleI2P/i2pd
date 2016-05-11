#include <cassert>
#include "../HTTP.h"

using namespace i2p::http;

int main(int argc, char *argv[]) {
  HTTPRes *res;
  int ret = 0, len = 0;
  const char *buf;

  buf =
    "HTTP/1.1 304 Not Modified\r\n"
    "Date: Thu, 14 Apr 2016 00:00:00 GMT\r\n"
    "Server: nginx/1.2.1\r\n"
    "Content-Length: 536\r\n"
    "\r\n";
  len = strlen(buf);
  res = new HTTPRes;
  assert((ret = res->parse(buf, len)) == len);
  assert(res->version == "HTTP/1.1");
  assert(res->status == "Not Modified");
  assert(res->code == 304);
  assert(res->headers.size() == 3);
  assert(res->headers.count("Date") == 1);
  assert(res->headers.count("Server") == 1);
  assert(res->headers.count("Content-Length") == 1);
  assert(res->headers.find("Date")->second == "Thu, 14 Apr 2016 00:00:00 GMT");
  assert(res->headers.find("Server")->second == "nginx/1.2.1");
  assert(res->headers.find("Content-Length")->second == "536");
  assert(res->is_chunked() == false);
  assert(res->length() == 536);
  delete res;

  return 0;
}

/* vim: expandtab:ts=2 */
