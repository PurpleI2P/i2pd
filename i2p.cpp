#include <iostream>
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
  i2p::util::HTTPServer httpServer (7070);	

  httpServer.Start ();	
  i2p::data::netdb.Start ();
  i2p::transports.Start ();	
  i2p::tunnel::tunnels.Start ();	
 
  sleep (1000);
  i2p::tunnel::tunnels.Stop ();	
  i2p::transports.Stop ();	
  i2p::data::netdb.Stop ();	
  httpServer.Stop ();		
  return 0;
}
