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
#include "util.h"

int main( int argc, char* argv[] )
{
  i2p::util::OptionParser(argc,argv);
#ifdef _WIN32
  setlocale(LC_CTYPE, "");
  SetConsoleCP(1251);
  SetConsoleOutputCP(1251);
  setlocale(LC_ALL, "Russian");
#endif

  //TODO: This is an ugly workaround. fix it.
  //TODO: Autodetect public IP.
  i2p::context.OverrideNTCPAddress(i2p::util::GetCharArg("--host", "127.0.0.1"), i2p::util::GetIntArg("--port", 17070));
  int httpport = i2p::util::GetIntArg("--httpport", 7070);

  i2p::util::HTTPServer httpServer (httpport);

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
