#include <cassert>
#include "../HTTP.h"

using namespace i2p::http;

int main() {
  std::map<std::string, std::string> params;
  URL *url;

  url = new URL;
  assert(url->parse("https://127.0.0.1:7070/asdasd?12345") == true);
  assert(url->schema == "https");
  assert(url->user == "");
  assert(url->pass == "");
  assert(url->host == "127.0.0.1");
  assert(url->port == 7070);
  assert(url->path == "/asdasd");
  assert(url->query == "12345");
  assert(url->to_string() == "https://127.0.0.1:7070/asdasd?12345");
  delete url;

  url = new URL;
  assert(url->parse("http://user:password@site.com:8080/asdasd?123456") == true);
  assert(url->schema == "http");
  assert(url->user == "user");
  assert(url->pass == "password");
  assert(url->host == "site.com");
  assert(url->port == 8080);
  assert(url->path == "/asdasd");
  assert(url->query == "123456");
  delete url;

  url = new URL;
  assert(url->parse("http://user:password@site.com/asdasd?name=value") == true);
  assert(url->schema == "http");
  assert(url->user == "user");
  assert(url->pass == "password");
  assert(url->host == "site.com");
  assert(url->port == 0);
  assert(url->path == "/asdasd");
  assert(url->query == "name=value");
  delete url;

  url = new URL;
  assert(url->parse("http://user:@site.com/asdasd?name=value1&name=value2") == true);
  assert(url->schema == "http");
  assert(url->user == "user");
  assert(url->pass == "");
  assert(url->host == "site.com");
  assert(url->port == 0);
  assert(url->path == "/asdasd");
  assert(url->query == "name=value1&name=value2");
  delete url;

  url = new URL;
  assert(url->parse("http://user@site.com/asdasd?name1=value1&name2&name3=value2") == true);
  assert(url->schema == "http");
  assert(url->user == "user");
  assert(url->pass == "");
  assert(url->host == "site.com");
  assert(url->port == 0);
  assert(url->path == "/asdasd");
  assert(url->query == "name1=value1&name2&name3=value2");
  assert(url->parse_query(params));
  assert(params.size() == 3);
  assert(params.count("name1") == 1);
  assert(params.count("name2") == 1);
  assert(params.count("name3") == 1);
  assert(params.find("name1")->second == "value1");
  assert(params.find("name2")->second == "");
  assert(params.find("name3")->second == "value2");
  delete url;

  url = new URL;
  assert(url->parse("http://@site.com:800/asdasd?") == true);
  assert(url->schema == "http");
  assert(url->user == "");
  assert(url->pass == "");
  assert(url->host == "site.com");
  assert(url->port == 800);
  assert(url->path == "/asdasd");
  assert(url->query == "");
  delete url;

  url = new URL;
  assert(url->parse("http://@site.com:17") == true);
  assert(url->schema == "http");
  assert(url->user == "");
  assert(url->pass == "");
  assert(url->host == "site.com");
  assert(url->port == 17);
  assert(url->path == "");
  assert(url->query == "");
  delete url;

  url = new URL;
  assert(url->parse("http://user:password@site.com:err_port/asdasd") == false);
  assert(url->schema == "http");
  assert(url->user == "user");
  assert(url->pass == "password");
  assert(url->host == "site.com");
  assert(url->port == 0);
  assert(url->path == "");
  assert(url->query == "");
  delete url;

  url = new URL;
  assert(url->parse("http://user:password@site.com:84/asdasd/@17#frag") == true);
  assert(url->schema == "http");
  assert(url->user == "user");
  assert(url->pass == "password");
  assert(url->host == "site.com");
  assert(url->port == 84);
  assert(url->path == "/asdasd/@17");
  assert(url->query == "");
  assert(url->frag == "frag");
  delete url;

  return 0;
}

/* vim: expandtab:ts=2 */
