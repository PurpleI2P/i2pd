/*
* Copyright (c) 2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TCP_SERVER_H__
#define TCP_SERVER_H__

#include <iostream>

#include <inttypes.h>
#include <string>
#include <memory>
#include <map>
#include <thread>
#include <boost/asio.hpp>
#include <sstream>
#include "HTTP.h"

namespace i2p 
{
namespace tcp
{

class TCPServer
{
private:
	const char *IpAddress = "127.0.0.1";
	int num = 1;
	int port = 49151;
    	char msg[8192];
    	bool resetBit = true;
    	int codeStop = 0;

    	sockaddr_in servAddr; 	
    	int serverSd;
	int bindStatus;

	sockaddr_in newSockAddr;
    	socklen_t newSockAddrSize;
    	int newSd;

	struct timeval start1;
	struct timeval end1;

	int bytesRead = 0; 
	int bytesWritten = 0;

	void _socker();
	void _bind();
	void _accept();
	void _recv();
	void _send();
	void _close();

public:	
	TCPServer(int _port);
	TCPServer(){};
	~TCPServer();
		
	void Printf();
	void Start();
	void Run();
	void Stop();
	int GetCodeStop();
};

} // tcp
} // i2p
#endif /* TCP_SERVER_H__ */
