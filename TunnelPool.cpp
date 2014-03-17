#include <cryptopp/dh.h>
#include "CryptoConst.h"
#include "Tunnel.h"
#include "NetDb.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "TunnelPool.h"

namespace i2p
{
namespace tunnel
{
	TunnelPool::TunnelPool (i2p::data::LocalDestination * localDestination, int numTunnels):
		m_LocalDestination (localDestination), m_NumTunnels (numTunnels), m_LastOutboundTunnel (nullptr)
	{
		CryptoPP::AutoSeededRandomPool rnd;
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(i2p::context.GetRandomNumberGenerator (), m_EncryptionPrivateKey, m_EncryptionPublicKey);
	}

	TunnelPool::~TunnelPool ()
	{
		for (auto it: m_InboundTunnels)
			it->SetTunnelPool (nullptr);
		for (auto it: m_OutboundTunnels)
			it->SetTunnelPool (nullptr);
	}

	void TunnelPool::TunnelCreated (InboundTunnel * createdTunnel)
	{
		m_InboundTunnels.insert (createdTunnel);
		if (m_LocalDestination)
			m_LocalDestination->UpdateLeaseSet ();
	}

	void TunnelPool::TunnelExpired (InboundTunnel * expiredTunnel)
	{
		m_InboundTunnels.erase (expiredTunnel);
		if (m_LocalDestination)
			m_LocalDestination->UpdateLeaseSet ();
	}	

	void TunnelPool::TunnelCreated (OutboundTunnel * createdTunnel)
	{
		m_OutboundTunnels.insert (createdTunnel);
	}

	void TunnelPool::TunnelExpired (OutboundTunnel * expiredTunnel)
	{
		m_OutboundTunnels.erase (expiredTunnel);
	}
		
	std::vector<InboundTunnel *> TunnelPool::GetInboundTunnels (int num) const
	{
		std::vector<InboundTunnel *> v;
		int i = 0;
		for (auto it : m_InboundTunnels)
		{
			if (i >= num) break;
			v.push_back (it);
			i++;	
		}	
		return v;
	}

	OutboundTunnel * TunnelPool::GetNextOutboundTunnel () 
	{
		if (m_OutboundTunnels.empty ()) return nullptr;
		auto tunnel = *m_OutboundTunnels.begin ();
		if (m_LastOutboundTunnel && tunnel == m_LastOutboundTunnel)
		{
			for (auto it: m_OutboundTunnels)
				if (it != m_LastOutboundTunnel)
				{
					tunnel = it;
					break;
				}	
		}
		m_LastOutboundTunnel = tunnel;
		return tunnel;
	}	
		
	void TunnelPool::CreateTunnels ()
	{
		int num = m_InboundTunnels.size ();
		for (int i = num; i < m_NumTunnels; i++)
			CreateInboundTunnel ();	
		num = m_OutboundTunnels.size ();
		for (int i = num; i < m_NumTunnels; i++)
			CreateOutboundTunnel ();	
	}

	void TunnelPool::CreateInboundTunnel ()
	{
		OutboundTunnel * outboundTunnel = m_OutboundTunnels.size () > 0 ? 
			*m_OutboundTunnels.begin () : tunnels.GetNextOutboundTunnel ();
		LogPrint ("Creating destination inbound tunnel...");
		auto firstHop = i2p::data::netdb.GetRandomRouter (outboundTunnel ? outboundTunnel->GetEndpointRouter () : nullptr); 
		auto secondHop = i2p::data::netdb.GetRandomRouter (firstHop);	
		auto * tunnel = tunnels.CreateTunnel<InboundTunnel> (
			new TunnelConfig (std::vector<const i2p::data::RouterInfo *>
				{                
			        firstHop, 
					secondHop
					// TODO: switch to 3-hops later	
					/*i2p::data::netdb.GetRandomRouter (secondHop) */
	            }),                 
			outboundTunnel);
		tunnel->SetTunnelPool (this);
	}

	void TunnelPool::CreateOutboundTunnel ()
	{
		InboundTunnel * inboundTunnel = m_InboundTunnels.size () > 0 ? 
			*m_InboundTunnels.begin () : tunnels.GetNextInboundTunnel ();
		if (inboundTunnel)
		{	
			LogPrint ("Creating destination outbound tunnel...");
			auto firstHop = i2p::data::netdb.GetRandomRouter (&i2p::context.GetRouterInfo ()); 
			auto secondHop = i2p::data::netdb.GetRandomRouter (firstHop);	
			auto * tunnel = tunnels.CreateTunnel<OutboundTunnel> (
				new TunnelConfig (std::vector<const i2p::data::RouterInfo *>
					{                
					    firstHop, 
						secondHop
			        },
					inboundTunnel->GetTunnelConfig ()));
			tunnel->SetTunnelPool (this);
		}	
	}	
}
}
