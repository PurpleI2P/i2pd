/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Destination.h"
#include "Identity.h"
#include "ClientContext.h"
#include "I2PService.h"
#include <boost/asio/error.hpp>

namespace i2p
{
namespace client
{
	static const i2p::data::SigningKeyType I2P_SERVICE_DEFAULT_KEY_TYPE = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;

	I2PService::I2PService (std::shared_ptr<ClientDestination> localDestination):
		m_LocalDestination (localDestination ? localDestination :
			i2p::client::context.CreateNewLocalDestination (false, I2P_SERVICE_DEFAULT_KEY_TYPE)),
			m_ReadyTimer(m_LocalDestination->GetService()),
			m_ReadyTimerTriggered(false),
			m_ConnectTimeout(0),
			isUpdated (true)
	{
		m_LocalDestination->Acquire ();
	}

	I2PService::I2PService (i2p::data::SigningKeyType kt):
		m_LocalDestination (i2p::client::context.CreateNewLocalDestination (false, kt)),
		m_ReadyTimer(m_LocalDestination->GetService()),
		m_ConnectTimeout(0),
		isUpdated (true)
	{
		m_LocalDestination->Acquire ();
	}

	I2PService::~I2PService ()
	{
		ClearHandlers ();
		if (m_LocalDestination) m_LocalDestination->Release ();
	}

	void I2PService::ClearHandlers ()
	{
		if(m_ConnectTimeout)
			m_ReadyTimer.cancel();
		std::unique_lock<std::mutex> l(m_HandlersMutex);
		for (auto it: m_Handlers)
			it->Terminate ();
		m_Handlers.clear();
	}

	void I2PService::SetConnectTimeout(uint32_t timeout)
	{
		m_ConnectTimeout = timeout;
	}

	void I2PService::AddReadyCallback(ReadyCallback cb)
	{
		uint32_t now = i2p::util::GetSecondsSinceEpoch();
		uint32_t tm = (m_ConnectTimeout) ? now + m_ConnectTimeout : NEVER_TIMES_OUT;

		LogPrint(eLogDebug, "I2PService::AddReadyCallback() ", tm, " ", now);
		m_ReadyCallbacks.push_back({cb, tm});
		if (!m_ReadyTimerTriggered) TriggerReadyCheckTimer();
	}

	void I2PService::TriggerReadyCheckTimer()
	{
		m_ReadyTimer.expires_from_now(boost::posix_time::seconds (1));
		m_ReadyTimer.async_wait(std::bind(&I2PService::HandleReadyCheckTimer, shared_from_this (), std::placeholders::_1));
		m_ReadyTimerTriggered = true;

	}

	void I2PService::HandleReadyCheckTimer(const boost::system::error_code &ec)
	{
		if(ec || m_LocalDestination->IsReady())
		{
			for(auto & itr : m_ReadyCallbacks)
				itr.first(ec);
			m_ReadyCallbacks.clear();
		}
		else if(!m_LocalDestination->IsReady())
		{
			// expire timed out requests
			uint32_t now = i2p::util::GetSecondsSinceEpoch ();
			auto itr = m_ReadyCallbacks.begin();
			while(itr != m_ReadyCallbacks.end())
			{
				if(itr->second != NEVER_TIMES_OUT && now >= itr->second)
				{
					itr->first(boost::asio::error::timed_out);
					itr = m_ReadyCallbacks.erase(itr);
				}
				else
					++itr;
			}
		}
		if(!ec && m_ReadyCallbacks.size())
			TriggerReadyCheckTimer();
		else
			m_ReadyTimerTriggered = false;
	}

	void I2PService::CreateStream (StreamRequestComplete streamRequestComplete, const std::string& dest, uint16_t port) {
		assert(streamRequestComplete);
		auto address = i2p::client::context.GetAddressBook ().GetAddress (dest);
		if (address)
			CreateStream(streamRequestComplete, address, port);
		else
		{
			LogPrint (eLogWarning, "I2PService: Remote destination not found: ", dest);
			streamRequestComplete (nullptr);
		}
	}

	void I2PService::CreateStream(StreamRequestComplete streamRequestComplete, std::shared_ptr<const Address> address, uint16_t port)
	{
		if(m_ConnectTimeout && !m_LocalDestination->IsReady())
		{
			AddReadyCallback([this, streamRequestComplete, address, port] (const boost::system::error_code & ec)
				{
					if(ec)
					{
						LogPrint(eLogWarning, "I2PService::CreateStream() ", ec.message());
						streamRequestComplete(nullptr);
					}
					else
					{
						if (address->IsIdentHash ())
							this->m_LocalDestination->CreateStream(streamRequestComplete, address->identHash, port);
						else
							this->m_LocalDestination->CreateStream (streamRequestComplete, address->blindedPublicKey, port);
					}
				});
		}
		else
		{
			if (address->IsIdentHash ())
				m_LocalDestination->CreateStream (streamRequestComplete, address->identHash, port);
			else
				m_LocalDestination->CreateStream (streamRequestComplete, address->blindedPublicKey, port);
		}
	}
}
}
