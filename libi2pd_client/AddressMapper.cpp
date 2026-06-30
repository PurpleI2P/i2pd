/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "AddressMapper.h"
#include <stdexcept>
#include "Log.h"
#include "Timestamp.h"

namespace i2p
{
namespace client
{
	static uint32_t PrefixToMask (int prefix)
	{
		return prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
	}

	bool AddressMapper::ParseCIDR (const std::string& cidr, boost::asio::ip::address_v4& base, int& prefix)
	{
		auto slash = cidr.find ('/');
		if (slash == std::string::npos) return false;
		std::string addrStr = cidr.substr (0, slash), prefStr = cidr.substr (slash + 1);
		if (addrStr.empty () || prefStr.empty ()) return false;
		// validate prefix is a plain positive integer
		for (char c : prefStr)
			if (c < '0' || c > '9') return false;
		try
		{
			auto addr = boost::asio::ip::make_address (addrStr);
			if (!addr.is_v4 ()) return false;
			int p = std::stoi (prefStr);
			if (p < 1 || p > 31) return false;
			base = addr.to_v4 ();
			prefix = p;
			return true;
		}
		catch (...) { return false; }
	}

	AddressMapper::AddressMapper (boost::asio::ip::address_v4 base, int prefix):
		m_Prefix (prefix), m_Cursor (1)
	{
		m_Mask = PrefixToMask (prefix);
		m_Base = base.to_uint () & m_Mask;
		m_Size = (uint64_t)1 << (32 - prefix);
	}

	AddressMapper::AddressMapper (const std::string& cidr):
		m_Cursor (1)
	{
		boost::asio::ip::address_v4 base;
		int prefix;
		if (!ParseCIDR (cidr, base, prefix))
			throw std::runtime_error ("Invalid virtual network CIDR: " + cidr);
		m_Prefix = prefix;
		m_Mask = PrefixToMask (prefix);
		m_Base = base.to_uint () & m_Mask;
		m_Size = (uint64_t)1 << (32 - prefix);
	}

	boost::asio::ip::address_v4 AddressMapper::Resolve (std::string_view name)
	{
		auto now = i2p::util::GetMillisecondsSinceEpoch ();
		std::lock_guard<std::mutex> l (m_Mutex);

		// 1. Already mapped? Refresh timestamp and return.
		auto fit = m_Forward.find (name);
		if (fit != m_Forward.end ())
		{
			uint32_t addr = fit->second;
			auto rit = m_Reverse.find (addr);
			if (rit != m_Reverse.end ())
			{
				rit->second.second = now;
				return boost::asio::ip::address_v4 (addr);
			}
			// forward says mapped but reverse is missing (shouldn't happen) — re-allocate
			m_Forward.erase (fit);
		}

		// 2. Scan forward from the cursor for the next free address. Skip the
		//    network address (offset 0) and the broadcast address (offset size-1).
		for (uint64_t tried = 0; tried < m_Size; tried++)
		{
			uint32_t off = (uint32_t)((m_Cursor + tried) % m_Size);
			if (off == 0 || off == m_Size - 1) continue;
			uint32_t addr = m_Base + off;
			if (m_Reverse.find (addr) == m_Reverse.end ())
			{
				std::string sname (name);
				m_Reverse.emplace (addr, NameTS (sname, now));
				m_Forward.emplace (std::move (sname), addr);
				m_Cursor = (uint32_t)((off + 1) % m_Size);
				return boost::asio::ip::address_v4 (addr);
			}
		}

		// 3. Range exhausted — evict the least-recently-used entry and reuse it.
		if (m_Reverse.empty ())
		{
			LogPrint (eLogError, "AddressMapper: virtual range too small to allocate");
			return boost::asio::ip::address_v4 (m_Base);
		}
		uint32_t evictAddr = 0;
		uint64_t minTs = (uint64_t)-1;
		for (const auto& it : m_Reverse)
			if (it.second.second < minTs) { minTs = it.second.second; evictAddr = it.first; }
		auto ev = m_Reverse.find (evictAddr);
		std::string oldName = ev->second.first;
		m_Reverse.erase (ev);
		m_Forward.erase (oldName);
		std::string sname (name);
		m_Reverse.emplace (evictAddr, NameTS (sname, now));
		m_Forward.emplace (std::move (sname), evictAddr);
		LogPrint (eLogWarning, "AddressMapper: virtual range full, evicted ", oldName);
		return boost::asio::ip::address_v4 (evictAddr);
	}

	std::string AddressMapper::GetName (const boost::asio::ip::address_v4& addr) const
	{
		std::lock_guard<std::mutex> l (m_Mutex);
		auto it = m_Reverse.find (addr.to_uint ());
		if (it != m_Reverse.end ())
			return it->second.first;
		return "";
	}

	void AddressMapper::Cleanup (uint64_t olderThanMs)
	{
		auto now = i2p::util::GetMillisecondsSinceEpoch ();
		std::lock_guard<std::mutex> l (m_Mutex);
		for (auto it = m_Reverse.begin (); it != m_Reverse.end ();)
		{
			if (now > it->second.second && now - it->second.second > olderThanMs)
			{
				m_Forward.erase (it->second.first);
				it = m_Reverse.erase (it);
			}
			else
				++it;
		}
	}

	bool AddressMapper::IsEmpty () const
	{
		std::lock_guard<std::mutex> l (m_Mutex);
		return m_Reverse.empty ();
	}
}
}
