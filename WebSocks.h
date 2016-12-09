#ifndef WEBSOCKS_H_
#define WEBSOCKS_H_
#include <string>

namespace i2p
{
namespace client
{

  class WebSocksImpl;

  /** @brief websocket socks proxy server */
  class WebSocks
  {
  public:
    WebSocks(const std::string & addr, int port);
    ~WebSocks();

    void Start();
    void Stop();

  private:
    WebSocksImpl * m_Impl;
  };
}
}
#endif
