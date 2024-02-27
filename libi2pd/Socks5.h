/*
* Copyright (c) 2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*
*/

#ifndef SOCKS5_H__
#define SOCKS5_H__

#include <string>
#include <memory>
#include <boost/asio.hpp>
#include "I2PEndian.h"

namespace i2p
{
namespace transport
{
	// SOCKS5 constants
	const uint8_t SOCKS5_VER = 0x05;
	const uint8_t SOCKS5_CMD_CONNECT = 0x01;
	const uint8_t SOCKS5_CMD_UDP_ASSOCIATE = 0x03;
	const uint8_t SOCKS5_ATYP_IPV4 = 0x01;
	const uint8_t SOCKS5_ATYP_IPV6 = 0x04;
	const uint8_t SOCKS5_ATYP_NAME = 0x03;
	const size_t SOCKS5_UDP_IPV4_REQUEST_HEADER_SIZE = 10;
	const size_t SOCKS5_UDP_IPV6_REQUEST_HEADER_SIZE = 22;

	const uint8_t SOCKS5_REPLY_SUCCESS = 0x00;
	const uint8_t SOCKS5_REPLY_SERVER_FAILURE = 0x01;
	const uint8_t SOCKS5_REPLY_CONNECTION_NOT_ALLOWED = 0x02;
	const uint8_t SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03;
	const uint8_t SOCKS5_REPLY_HOST_UNREACHABLE = 0x04;
	const uint8_t SOCKS5_REPLY_CONNECTION_REFUSED = 0x05;
	const uint8_t SOCKS5_REPLY_TTL_EXPIRED = 0x06;
	const uint8_t SOCKS5_REPLY_COMMAND_NOT_SUPPORTED = 0x07;
	const uint8_t SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
	
	// SOCKS5 handshake
	template<typename Socket, typename Handler>
	void Socks5ReadReply (Socket& s, Handler handler)
	{
		auto readbuff = std::make_shared<std::vector<int8_t> >(258); // max possible
		boost::asio::async_read(s, boost::asio::buffer(readbuff->data (), 5), boost::asio::transfer_all(), // read 4 bytes of header + first byte of address
			[readbuff, &s, handler](const boost::system::error_code& ec, std::size_t transferred)
			{
				if (!ec)
				{    
				    if ((*readbuff)[1] == SOCKS5_REPLY_SUCCESS)
				    {
						size_t len = 0;
						switch ((*readbuff)[3]) // ATYP
						{
							case SOCKS5_ATYP_IPV4: len = 3; break; // address length 4 bytes
							case SOCKS5_ATYP_IPV6: len = 15; break; // address length 16 bytes
							case SOCKS5_ATYP_NAME: len += (*readbuff)[4]; break; // first byte of address is length
							default: ;
						}	
						if (len)
						{
							len += 2; // port
							boost::asio::async_read(s, boost::asio::buffer(readbuff->data (), len), boost::asio::transfer_all(),
								[readbuff, handler](const boost::system::error_code& ec, std::size_t transferred)
								{
									if (!ec)
										handler (boost::system::error_code ()); // success
									else
										handler (boost::asio::error::make_error_code (boost::asio::error::connection_aborted));
								});		
						}	
						else
							handler (boost::asio::error::make_error_code (boost::asio::error::fault)); // unknown address type 
				    }
				    else	
						switch ((*readbuff)[1]) // REP
						{
							case SOCKS5_REPLY_SERVER_FAILURE:
								handler (boost::asio::error::make_error_code (boost::asio::error::access_denied ));
							break;	
							case SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:
								handler (boost::asio::error::make_error_code (boost::asio::error::no_permission));
							break;	
							case SOCKS5_REPLY_HOST_UNREACHABLE:
								handler (boost::asio::error::make_error_code (boost::asio::error::host_unreachable));
							break;
							case SOCKS5_REPLY_NETWORK_UNREACHABLE:
								handler (boost::asio::error::make_error_code (boost::asio::error::network_unreachable));
							break;
							case SOCKS5_REPLY_CONNECTION_REFUSED:
								handler (boost::asio::error::make_error_code (boost::asio::error::connection_refused));
							break;
							case SOCKS5_REPLY_TTL_EXPIRED:
								handler (boost::asio::error::make_error_code (boost::asio::error::timed_out));
							break;	
							case SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:
								handler (boost::asio::error::make_error_code (boost::asio::error::operation_not_supported));
							break;	
							case SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
								handler (boost::asio::error::make_error_code (boost::asio::error::no_protocol_option));
							break;	
							default:
				        		handler (boost::asio::error::make_error_code (boost::asio::error::connection_aborted)); 
						}
				}
				else
				   handler (ec); 
			});
	}	
	
	template<typename Socket, typename Handler>
	void Socks5Connect (Socket& s, Handler handler, std::shared_ptr<std::vector<uint8_t> > buff, uint16_t port)
	{
		if (buff && buff->size () >= 6)
		{
		    (*buff)[0] = SOCKS5_VER;
			(*buff)[1] = SOCKS5_CMD_CONNECT;
			(*buff)[2] = 0x00;
			htobe16buf(buff->data () + buff->size () - 2, port);
		    boost::asio::async_write(s, boost::asio::buffer(*buff), boost::asio::transfer_all(),
				[buff, &s, handler](const boost::system::error_code& ec, std::size_t transferred)
				{
		            (void) transferred;
					if (!ec)
		           		Socks5ReadReply (s, handler);
					else
		                handler (ec);
				});
		}
		else
		    handler (boost::asio::error::make_error_code (boost::asio::error::no_buffer_space));
	}

	template<typename Socket, typename Handler>
	void Socks5Connect (Socket& s, const boost::asio::ip::tcp::endpoint& ep, Handler handler)
	{
		std::shared_ptr<std::vector<uint8_t> > buff;
		if(ep.address ().is_v4 ())
		{
		    buff = std::make_shared<std::vector<uint8_t> >(10);
			(*buff)[3] = SOCKS5_ATYP_IPV4;
			auto addrbytes = ep.address ().to_v4().to_bytes();
			memcpy(buff->data () + 4, addrbytes.data(), 4);
		}
		else if (ep.address ().is_v6 ())
		{
		    buff = std::make_shared<std::vector<uint8_t> >(22);
			(*buff)[3] = SOCKS5_ATYP_IPV6;
			auto addrbytes = ep.address ().to_v6().to_bytes();
			memcpy(buff->data () + 4, addrbytes.data(), 16);
		}
		if (buff)
		    Socks5Connect (s, handler, buff, ep.port ());
		else
		    handler (boost::asio::error::make_error_code (boost::asio::error::fault));  
	}

	template<typename Socket, typename Handler>
	void Socks5Connect (Socket& s, const std::pair<std::string, uint16_t>& ep, Handler handler)
	{
		auto& addr = ep.first;
		if (addr.length () <= 255) 
		{
		    auto buff = std::make_shared<std::vector<uint8_t> >(addr.length () + 7);
		    (*buff)[3] = SOCKS5_ATYP_NAME;
		    (*buff)[4] = addr.length (); 
		    memcpy (buff->data () + 5, addr.c_str (), addr.length ());
		    Socks5Connect (s, handler, buff, ep.second);    
		}
		else
		    handler (boost::asio::error::make_error_code (boost::asio::error::name_too_long));
	}


	template<typename Socket, typename Endpoint, typename Handler>
	void Socks5Handshake (Socket& s, Endpoint ep, Handler handler)
	{
		static const uint8_t methodSelection[3] = { SOCKS5_VER, 0x01, 0x00 }; // 1 method, no auth
		boost::asio::async_write(s, boost::asio::buffer(methodSelection, 3), boost::asio::transfer_all(),
			[&s, ep, handler] (const boost::system::error_code& ec, std::size_t transferred)
			{
				(void) transferred;
		        if (!ec)
		        {
		            auto readbuff = std::make_shared<std::vector<uint8_t> >(2);
		            boost::asio::async_read(s, boost::asio::buffer(*readbuff), boost::asio::transfer_all(),
		                [&s, ep, handler, readbuff] (const boost::system::error_code& ec, std::size_t transferred)
			            {
		                    if (!ec)
		                    {
		                        if (transferred == 2 && (*readbuff)[1] == 0x00) // no auth
		                            Socks5Connect (s, ep, handler);
		                        else
		                            handler (boost::asio::error::make_error_code (boost::asio::error::invalid_argument)); 
		                    }
		                    else 
		                        handler (ec);
		                });
		        }
		        else
		            handler (ec);
			});
	}
	
}
}

#endif
