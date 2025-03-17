/*
* Copyright (c) 2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*
*/

#include "Transports.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{
	void TunnelTransportSender::SendMessagesTo (const i2p::data::IdentHash& to,
		std::list<std::shared_ptr<I2NPMessage> >&& msgs)
	{
		if (msgs.empty ()) return;
		auto currentTransport = m_CurrentTransport.lock ();
		if (!currentTransport)
		{
			// try to obtain transport from pending request or send thought transport is not complete
			if (m_PendingTransport.valid ()) // pending request?
			{
				if (m_PendingTransport.wait_for(std::chrono::seconds(0)) == std::future_status::ready) 
				{	
					// pending request complete
					currentTransport = m_PendingTransport.get (); // take transports used in pending request
					if (currentTransport)
					{	
						if (currentTransport->IsEstablished ()) 
							m_CurrentTransport = currentTransport;
						else
							currentTransport = nullptr;
					}
				}	
				else // still pending
				{	
					// send through transports, but don't update pending transport
					i2p::transport::transports.SendMessages (to, std::move (msgs));
					return;
				}	
			}
		}
		if (currentTransport) // session is good
			// send to session directly
			currentTransport->SendI2NPMessages (msgs);
		else // no session yet
			// send through transports
			m_PendingTransport = i2p::transport::transports.SendMessages (to, std::move (msgs));

	}

	void TunnelTransportSender::SendMessagesTo (const i2p::data::IdentHash& to,
		std::list<std::shared_ptr<I2NPMessage> >& msgs)
	{
		std::list<std::shared_ptr<i2p::I2NPMessage> > msgs1;
		msgs.swap (msgs1);
		SendMessagesTo (to, std::move (msgs1));
	}	

	void TunnelTransportSender::Reset ()
	{
		m_CurrentTransport.reset ();
		if (m_PendingTransport.valid ())
			m_PendingTransport = std::future<std::shared_ptr<i2p::transport::TransportSession> >();
	}	
}
}
