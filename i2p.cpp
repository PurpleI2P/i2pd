#include <iostream>
#include <thread>
#include <cryptopp/integer.h>
#include "Log.h"
#include "base64.h"
#include "Transports.h"
#include "NTCPSession.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "NetDb.h"
#include "HTTPServer.h"

int main( int, char** ) 
{

#ifdef _WIN32
  setlocale(LC_CTYPE, "");
  SetConsoleCP(1251);
  SetConsoleOutputCP(1251);
  setlocale(LC_ALL, "Russian");
#endif

  i2p::util::HTTPServer httpServer (7070);	

  httpServer.Start ();	
  i2p::data::netdb.Start ();
  i2p::transports.Start ();	
  i2p::tunnel::tunnels.Start ();	
 
  std::this_thread::sleep_for (std::chrono::seconds(10000)); 
  i2p::tunnel::tunnels.Stop ();	
  i2p::transports.Stop ();	
  i2p::data::netdb.Stop ();	
  httpServer.Stop ();		
  return 0;
}
