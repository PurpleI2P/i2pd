#include <cassert>
#include "HTTP.h"

using namespace i2p::http;

int main() {
  HTTPReq *req;
  int ret = 0, len = 0;
  const char *buf;

  /* test: parsing request with body */
  buf =
    "GET / HTTP/1.0\r\n"
    "User-Agent: curl/7.26.0\r\n"
    "Host: inr.i2p\r\n"
    "Accept: */*\r\n"
    "\r\n"
    "test";
  len = strlen(buf);
  req = new HTTPReq;
  assert((ret = req->parse(buf, len)) == len - 4);
  assert(req->version == "HTTP/1.0");
  assert(req->method == "GET");
  assert(req->uri == "/");
  assert(req->GetNumHeaders () == 3);
  assert(req->GetNumHeaders("Host") == 1);
  assert(req->GetNumHeaders("Accept") == 1);
  assert(req->GetNumHeaders("User-Agent") == 1);
  assert(req->GetHeader("Host")  == "inr.i2p");
  assert(req->GetHeader("Accept") == "*/*");
  assert(req->GetHeader("User-Agent")  == "curl/7.26.0");
  delete req;

  /* test: parsing request without body */
  buf =
    "GET / HTTP/1.0\r\n"
    "\r\n";
  len = strlen(buf);
  req = new HTTPReq;
  assert((ret = req->parse(buf, len)) == len);
  assert(req->version == "HTTP/1.0");
  assert(req->method == "GET");
  assert(req->uri == "/");
  assert(req->GetNumHeaders () == 0);
  delete req;

  /* test: parsing request without body */
  buf =
    "GET / HTTP/1.1\r\n"
    "\r\n";
  len = strlen(buf);
  req = new HTTPReq;
  assert((ret = req->parse(buf, len)) > 0);
  delete req;

  /* test: parsing incomplete request */
  buf =
    "GET / HTTP/1.0\r\n"
    "";
  len = strlen(buf);
  req = new HTTPReq;
  assert((ret = req->parse(buf, len)) == 0); /* request not completed */
  delete req;

  /* test: parsing slightly malformed request */
  buf =
    "GET http://inr.i2p HTTP/1.1\r\n"
    "Host:  stats.i2p\r\n"
    "Accept-Encoding: \r\n"
    "Accept: */*\r\n"
    "\r\n";
  len = strlen(buf);
  req = new HTTPReq;
  assert((ret = req->parse(buf, len)) == len); /* no host header */
  assert(req->method == "GET");
  assert(req->uri == "http://inr.i2p");
  assert(req->GetNumHeaders () == 3);
  assert(req->GetNumHeaders("Host") == 1);
  assert(req->GetNumHeaders("Accept") == 1);
  assert(req->GetNumHeaders("Accept-Encoding") == 1);
  assert(req->GetHeader("Host") == "stats.i2p");
  assert(req->GetHeader("Accept") == "*/*");
  assert(req->GetHeader("Accept-Encoding") == "");
  delete req;

  return 0;
}

/* vim: expandtab:ts=2 */
