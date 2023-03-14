/*
* Copyright (c) 2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/
#include "TCPServer.h"
#include <iostream>
#include <netinet/in.h>
#include <string>
//#include <sys/socket.h>
#include <sys/time.h>
#include <sstream>

#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>

#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>

#include <iomanip>
#include <thread>
#include <memory>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>

#include "Base.h"
#include "FS.h"
#include "Log.h"
#include "Config.h"
#include "Tunnel.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "LeaseSet.h"
#include "Destination.h"
#include "RouterContext.h"
#include "ClientContext.h"
#include "Daemon.h"
#include "util.h"
#include "ECIESX25519AEADRatchetSession.h"
#include "I18N.h"

#ifdef WIN32_APP
#include "Win32App.h"
#endif

// For image, style and info
#include "version.h"

namespace i2p 
{
namespace tcp 
{
// Private region.-------------------------------------------------------------------------------
// Part: Connection.
	void TCPServer::_socker()
	{
		bzero((char*)&servAddr, sizeof(servAddr));
		servAddr.sin_family = AF_INET;
		servAddr.sin_addr.s_addr = inet_addr(IpAddress);
		servAddr.sin_port = htons(port);
		
		serverSd = socket(AF_INET, SOCK_STREAM, 0);
		if(serverSd < 0)
		{
			std::cerr << "[!] - Error establishing the server socket" << std::endl;
			exit(0);
		}
	}

	void TCPServer::_bind()
	{
		bindStatus = bind(serverSd, (struct sockaddr*) &servAddr, sizeof(servAddr));
		if(bindStatus < 0)
		{
			std::cerr << "[!] - Error binding socket to local address" << std::endl;
			codeStop = 2;
		}
    		
    		std::cout << "[*] - Waiting for a client to connect..." << std::endl;
    		listen(serverSd, 1);
	}
	
	void TCPServer::_accept()
	{
		newSockAddrSize = sizeof(newSockAddr);
		newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
		
		if(newSd < 0)
		{
			std::cerr << "[!] - Error accepting request from client!" << std::endl;
			codeStop = 3;
		}
		else
		{
			std::cout << "[*] - Connected with client!" << std::endl;
		}
	}
	
	void TCPServer::_close()
	{
		std::cout << "[-] - Start close socket..." << std::endl;
		gettimeofday(&end1, NULL);
		close(newSd);
		close(serverSd);
		std::cout << "[-] - End close socket..." << std::endl;
	}
//End part: Connection.
// Part: Static.
	static void showUptime(std::stringstream& s, int seconds)
	{
		int num;

		if ((num = seconds / 86400) > 0) {
			s << ntr("%d day", "%d days", num, num) << ", ";
			seconds -= num * 86400;
		}
		if ((num = seconds / 3600) > 0) {
			s << ntr("%d hour", "%d hours", num, num) << ", ";
			seconds -= num * 3600;
		}
		if ((num = seconds / 60) > 0) {
			s << ntr("%d minute", "%d minutes", num, num) << ", ";
			seconds -= num * 60;
		}
		s << ntr("%d second", "%d seconds", seconds, seconds);
	}
	
	static void showStatus(std::stringstream& s, i2p::RouterStatus status)
	{
		switch (status)
		{
			case eRouterStatusOK: s << tr("OK."); break;
			case eRouterStatusTesting: s << tr("Testing."); break;
			case eRouterStatusFirewalled: s << tr("Firewalled."); break;
			case eRouterStatusUnknown: s << tr("Unknown."); break;
			case eRouterStatusProxy: s << tr("Proxy."); break;
			case eRouterStatusMesh: s << tr("Mesh."); break;
			default: s << tr("Unknown (default).");
		}
	}

	static void showTraffic(std::stringstream& s, uint64_t bytes)
	{
		s << std::fixed << std::setprecision(2);
		auto numKBytes = (double) bytes / 1024;
		if (numKBytes < 1024)
			s << tr(/* tr: Kibibyte */ "%.2f KiB", numKBytes);
		else if (numKBytes < 1024 * 1024)
			s << tr(/* tr: Mebibyte */ "%.2f MiB", numKBytes / 1024);
		else
			s << tr(/* tr: Gibibyte */ "%.2f GiB", numKBytes / 1024 / 1024);
	}
	
	template<typename Sessions>
	static void ShowTransportSessions (std::stringstream& s, const Sessions& sessions, const std::string name)
	{
		auto comp = [](typename Sessions::mapped_type a, typename Sessions::mapped_type b)
		{ 
			return a->GetRemoteEndpoint() < b->GetRemoteEndpoint(); 
		};
		
		std::set<typename Sessions::mapped_type, decltype(comp)> sortedSessions(comp);
		for (const auto& it : sessions)
		{
			auto ret = sortedSessions.insert(it.second);
			if (!ret.second)
				LogPrint(eLogError, "TCPPServer: Duplicate remote endpoint detected: ", (*ret.first)->GetRemoteEndpoint());
		}
		
		std::stringstream tmp_s, tmp_s6; uint16_t cnt = 0, cnt6 = 0;
		for (const auto& it: sortedSessions)
		{
			auto endpoint = it->GetRemoteEndpoint();
			
			if (it && it->IsEstablished() && endpoint.address().is_v4 ())
			{
				tmp_s << i2p::data::GetIdentHashAbbreviation(it->GetRemoteIdentity()->GetIdentHash()) << ": " 
				      << endpoint.address ().to_string () << ":" << endpoint.port ();

				tmp_s << " [" << it->GetNumSentBytes () << ":" << it->GetNumReceivedBytes () << "]";

				if (it->GetRelayTag ())
					tmp_s << " [itag:" << it->GetRelayTag () << "]";

				if (it->GetSendQueueSize () > 0)
					tmp_s << " [queue:" << it->GetSendQueueSize () << "]";

				tmp_s << std::endl;
				cnt++;
			}
			if (it && it->IsEstablished() && endpoint.address().is_v6 ())
			{
				tmp_s6 << i2p::data::GetIdentHashAbbreviation(it->GetRemoteIdentity()->GetIdentHash()) << ": "
					<< "[" << endpoint.address ().to_string () << "]:" << endpoint.port ();

				tmp_s6 << " [" << it->GetNumSentBytes () << ":" << it->GetNumReceivedBytes () << "]";
				
				if (it->GetRelayTag ())
					tmp_s6 << " [itag:" << it->GetRelayTag () << "]";
				
				if (it->GetSendQueueSize () > 0)
					tmp_s6 << " [queue:" << it->GetSendQueueSize () << "]";
				
				tmp_s6 << std::endl;
				cnt6++;
			}
		}
		if (!tmp_s.str().empty())
		{
			s << name << "(" << cnt << ")\n" << tmp_s.str() << "\n";
		}
		if (!tmp_s6.str().empty())
		{
			s << name << "v6 ( " << cnt6 << " )\n" << tmp_s6.str() << "\n";
		}
	}
//End part: Loacal.
//End private region.---------------------------------------------------------------------------	
// Publick region-------------------------------------------------------------------------------
	TCPServer::TCPServer(int _port)
	{
		port = _port;
	}
	
	TCPServer::~TCPServer()
	{
		_close();
		//std::cout << "********Session********" << std::endl;
		//std::cout << "[i] - Bytes written: " << bytesWritten << " | Bytes read: " << bytesRead << std::endl;
		//std::cout << "[i] - Elapsed time: " << (end1.tv_sec - start1.tv_sec) << " secs." << std::endl;
		//std::cout << "[-] - Connection closed..." << std::endl;
	}

	void TCPServer::Printf()
	{
		std::cout << "[*] - Address: 127.0.0.1 (default)" << std::endl;
		std::cout << "[*] - Port: " << port << std::endl;
	}
	
	void TCPServer::Start()
	{	
		while(codeStop == 0)
		{
			std::cout << "[i] - Init socket." << std::endl;
			_socker();

			std::cout << "[i] - Start bind." << std::endl;
			_bind();

			std::cout << "[i] - Server status: \"RUN\"." << std::endl;
			_accept();

			start1.tv_sec = 0;
			end1.tv_sec = 0;

			gettimeofday(&start1, NULL);
			
			while(resetBit)
			{
				try
				{
					//receive a message from the client (listen)
					std::cout << "[i] - Awaiting client response..." << std::endl;
					memset(&msg, 0, sizeof(msg));//clear the buffer
					bytesRead += recv(newSd, (char*)&msg, sizeof(msg), 0);

					if(!strcmp(msg, "@:clear") || !strcmp(msg, "@:cls"))
					{
						system("clear");
						strcpy(msg, "Bot -> test status: \"Server clear\" - ok.");
						bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
					}
					else if(!strcmp(msg, "@:hi"))
					{
						std::cout << "[*] - Client send command \"hi\"." << std::endl;
						strcpy(msg, "Bot -> status msg: \"Good!\" ;)");
						bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
					}
					else if(!strcmp(msg, "@:info"))
					{
						try
						{
							std::cout << "[*] - Client send command \"info\"." << std::endl;

							std::stringstream s;
							
							s << "\n\n---=== Base info I2PD. ===---\n";
							
							// Output: Status.
							s << "\n";
							i2p::RouterStatus status = i2p::context.GetStatus();
							s << "> Status: ";	
							showStatus(s, status);

							// Output: Uptime.
							s << "\n";
							int uptime = i2p::context.GetUptime();
							s << "> Uptime: ";
							showUptime(s, uptime);

							// Output: Tunnel creation success rate.
							s << "\n";
							s << "> Tunnel creation success rate: " << i2p::tunnel::tunnels.GetTunnelCreationSuccessRate() << "%";

							// Output: Received.
							s << "\n";
							s << "> Received: ";
							showTraffic(s, i2p::transport::transports.GetTotalReceivedBytes());					
							s << " ("<<tr(/* tr: Kibibyte/s */ "%.2f KiB/s",(double)i2p::transport::transports.GetInBandwidth15s()/1024)<<").";

							// Output: Sent.
							s << "\n";
							s << "> Sent: ";
							showTraffic (s, i2p::transport::transports.GetTotalSentBytes());
							s << " ("<<tr(/* tr: Kibibyte/s */ "%.2f KiB/s",(double)i2p::transport::transports.GetOutBandwidth15s()/1024)<<").";

							// Output: Transit.
							s << "\n";
							s << "> Transit: ";
							showTraffic(s, i2p::transport::transports.GetTotalTransitTransmittedBytes());
							s << " ("<<tr(/* tr: Kibibyte/s */ "%.2f KiB/s",(double)i2p::transport::transports.GetTransitBandwidth15s()/1024)<<").";

							// Output: Router Ident.
							s << "\n";
							s << "> Router Ident: " << i2p::context.GetRouterInfo().GetIdentHashBase64();

							// Output: Base info.
							s << "\n";
							s << "> Router Caps: " << i2p::context.GetRouterInfo().GetProperty("caps");

							s << "\n";
							s << "> Version: " << VERSION;

							s << "\n";
							s << "> Routers: " << i2p::data::netdb.GetNumRouters() << ".";

							s << "\n";
							s << "> Floodfills: " << i2p::data::netdb.GetNumFloodfills () << ".";

							s << "\n";
							s << "> LeaseSets: " << i2p::data::netdb.GetNumLeaseSets () << ".";

							size_t clientTunnelCount = i2p::tunnel::tunnels.CountOutboundTunnels();
							clientTunnelCount += i2p::tunnel::tunnels.CountInboundTunnels();
							size_t transitTunnelCount = i2p::tunnel::tunnels.CountTransitTunnels();

							s << "\n";
							s << "> Client Tunnels: " << std::to_string(clientTunnelCount) << ".";;

							s << "\n";
							s << "> Transit Tunnels: " << std::to_string(transitTunnelCount) << ".";

							s << "\n\n---=== Info tunnelse I2PD. ===---\n\n";

							s << "Client Tunnels:";
							auto httpProxy = i2p::client::context.GetHttpProxy();
							if(httpProxy)
							{
								s << "\n";
								auto& ident = httpProxy->GetLocalDestination()->GetIdentHash();
								s << "HTTP Proxy - " << i2p::client::context.GetAddressBook().ToAddress(ident);;
							}

							auto socksProxy = i2p::client::context.GetSocksProxy();
							if(socksProxy)
							{
								s << "\n";
								auto& ident = socksProxy->GetLocalDestination()->GetIdentHash();
								s << "SOCKS Proxy - " << i2p::client::context.GetAddressBook().ToAddress(ident);
							}
							
							auto& clientTunnels = i2p::client::context.GetClientTunnels();
							if(!clientTunnels.empty())
							{
								s << "\n";
								for (auto& it: clientTunnels)
								{
									auto& ident = it.second->GetLocalDestination()->GetIdentHash();
									s << it.second->GetName() << " - ";
									s << i2p::client::context.GetAddressBook().ToAddress(ident) << "\n";
								}
							}

							auto& serverTunnels = i2p::client::context.GetServerTunnels();
							if(!serverTunnels.empty()) 
							{
								s << "\n";
								s << "Server Tunnels:" << "\n";
								for(auto& it: serverTunnels)
								{
									auto& ident = it.second->GetLocalDestination()->GetIdentHash();
									s << it.second->GetName() << " - ";
									s << i2p::client::context.GetAddressBook().ToAddress(ident);
									s << ":" << it.second->GetLocalPort() << "\n";
								}
							}
							
							auto& clientForwards = i2p::client::context.GetClientForwards();
							if(!clientForwards.empty())
							{
								s << "\n";
								s << "Client Forwards:" << "\n";
								for (auto& it: clientForwards)
								{
									auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
									s << it.second->GetName() << " - ";
									s << i2p::client::context.GetAddressBook().ToAddress(ident) << "\n";
								}
							}

							auto& serverForwards = i2p::client::context.GetServerForwards();
							if(!serverForwards.empty())
							{
								s << "\n";
								s << "Server Forwards:\n";
								for(auto& it: serverForwards)
								{
									auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
									s << it.second->GetName() << " - ";
									s << i2p::client::context.GetAddressBook().ToAddress(ident) << "\n";
								}
							}

							// Convert and send msg.
							const std::string tmp = s.str();
							strcpy(msg, tmp.c_str());
							//std::cout << "[i] - " << msg;		
							bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
						}
						catch(const char* msg)
						{
							std::cout << msg << std::endl;					
						}
					}
					else if(!strcmp(msg, "@:tr"))
					{
						std::cout << "[*] - Client send command \"transport\"." << std::endl;
						std::stringstream s;
						s << "\n\n---=== Transport info I2PD. ===---\n";

						auto ntcp2Server = i2p::transport::transports.GetNTCP2Server();
						if (ntcp2Server)
						{
							auto sessions = ntcp2Server->GetNTCP2Sessions();
							if (!sessions.empty ())
								ShowTransportSessions(s, sessions, "NTCP2");
						}
						auto ssu2Server = i2p::transport::transports.GetSSU2Server();
						if (ssu2Server)
						{
							auto sessions = ssu2Server->GetSSU2Sessions();
							if (!sessions.empty())
								ShowTransportSessions(s, sessions, "SSU2");
						}

						// Convert and send msg.
						const std::string tmp = s.str();
						strcpy(msg, tmp.c_str());
						//std::cout << "[i] - " << msg << std::endl;		
						bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
					}
					else if(!strcmp(msg, "@:?"))
					{
						std::stringstream s;
						std::cout << "\n[*] - Client send command \"call helper\"." << std::endl;
						s << "\nHelper server v0.0.2\n";
						s << "@:info - Output base info about i2pd router.\n";
						s << "@:tr - Output info transport i2pd.\n";
						s << "@:exit - close console i2pd client.\n";
						s << "@:stop - kill i2pd service and exit.\n";
						s << "[+] - End help.";

						const std::string tmp = s.str();
						strcpy(msg, tmp.c_str());
						bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
					}
					else if(!strcmp(msg, "@:stop"))
					{
						std::cout << "[*] - Client send command \"stop\"." << std::endl;
						strcpy(msg, "Bot -> Server is stop.");
						bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
						codeStop = 1;
						system("killall -s 9 ./i2pd");
						break;
					}
					else if(strcmp(msg, ""))
					{
						std::cout << "[*] - Client send command: " << std::endl;
						strcpy(msg, "Bot -> command status: \"Bad!\" :(");
						bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
					}
					else
					{
						std::cout << "[!] - Disconnecting from the client!" << std::endl;
						std::cout << "[-] - Restart server..." << std::endl;
						break;	
					}

					//Output send msg (side server).
					//std::cout << "[>] - Server send: " << msg << std::endl;
				}
				catch(const char* msg)
				{
					std::cout << "[!] - Disconnecting from the client." << std::endl;
					std::cout << msg << std::endl;
					break;
				}
			}
			
			_close();
			
			if(codeStop >= 1)
			{
				std::cout << "[!] - Exit TCP server... \n" << "Stop code = " << codeStop << "\n";
				break;
			}		
		}	
	}
	
	void TCPServer::Stop()
	{
		codeStop = 1;
		resetBit = false;
		std::cout << "[-] - Call distruct TCPServer, stop." << std::endl;
		_close();
	}
	
	int TCPServer::GetCodeStop()
	{
		return codeStop;
	}
} // tcp
} // i2p
