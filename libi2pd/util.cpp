/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <cstdlib>
#include <string>
#include <unordered_set>
#include <boost/asio.hpp>

#include "util.h"
#include "Log.h"
#include "I2PEndian.h"

#if !defined (__FreeBSD__) && !defined(_MSC_VER)
#include <pthread.h>
#endif

#if defined(__OpenBSD__) || defined(__FreeBSD__)
#include <pthread_np.h>
#endif

#if defined(__APPLE__)
# include <AvailabilityMacros.h>
#endif

#if defined(__HAIKU__)
#include <gnu/pthread.h>
#include <posix/pthread.h>
#include <posix/sys/sockio.h>
#include <posix/sys/ioctl.h>
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#include <bsd/ifaddrs.h>
#endif
#endif

#ifdef _WIN32
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sysinfoapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shlobj.h>

#if defined(_MSC_VER)
const DWORD MS_VC_EXCEPTION = 0x406D1388;
#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType;
	LPCSTR szName;
	DWORD dwThreadID;
	DWORD dwFlags;
} THREADNAME_INFO;
#pragma pack(pop)
#endif

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

// inet_pton and inet_ntop have been in Windows since Vista, but XP doesn't have these functions!
// This function was written by Petar Korponai?. See http://stackoverflow.com/questions/15660203/inet-pton-identifier-not-found
int inet_pton_xp (int af, const char *src, void *dst)
{
	struct sockaddr_storage ss;
	int size = sizeof (ss);
	char src_copy[INET6_ADDRSTRLEN + 1];

	ZeroMemory (&ss, sizeof (ss));
	strncpy (src_copy, src, INET6_ADDRSTRLEN + 1);
	src_copy[INET6_ADDRSTRLEN] = 0;

	if (WSAStringToAddress (src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0)
	{
		switch (af)
		{
		case AF_INET:
			*(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
			return 1;
		case AF_INET6:
			*(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
			return 1;
		}
	}
	return 0;
}

const char *inet_ntop_xp(int af, const void *src, char *dst, socklen_t size)
{
	struct sockaddr_storage ss;
	unsigned long s = size;

	ZeroMemory(&ss, sizeof(ss));
	ss.ss_family = af;

	switch (af)
	{
		case AF_INET:
			((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
			break;
		default:
			return NULL;
	}
	/* cannot directly use &size because of strict aliasing rules */
	return (WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0)? dst : NULL;
}

#else /* !_WIN32 => UNIX */
#include <sys/types.h>
#ifdef ANDROID
#include "ifaddrs.h"
#else
#include <ifaddrs.h>
#endif
#endif

#define address_pair_v4(a,b) { boost::asio::ip::address_v4::from_string (a).to_ulong (), boost::asio::ip::address_v4::from_string (b).to_ulong () }
#define address_pair_v6(a,b) { boost::asio::ip::address_v6::from_string (a).to_bytes (), boost::asio::ip::address_v6::from_string (b).to_bytes () }

namespace i2p
{
namespace util
{

	void RunnableService::StartIOService ()
	{
		if (!m_IsRunning)
		{
			m_IsRunning = true;
			m_Thread.reset (new std::thread (std::bind (& RunnableService::Run, this)));
		}
	}

	void RunnableService::StopIOService ()
	{
		if (m_IsRunning)
		{
			m_IsRunning = false;
			m_Service.stop ();
			if (m_Thread)
			{
				m_Thread->join ();
				m_Thread = nullptr;
			}
		}
	}

	void RunnableService::Run ()
	{
		SetThreadName(m_Name.c_str());

		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, m_Name, ": Runtime exception: ", ex.what ());
			}
		}
	}

	void SetThreadName (const char *name) {
#if defined(__APPLE__)
# if (!defined(MAC_OS_X_VERSION_10_6) || \
		(MAC_OS_X_VERSION_MAX_ALLOWED < 1060) || \
		defined(__POWERPC__))
		/* pthread_setname_np is not there on <10.6 and all PPC.
		So do nothing. */
# else
		pthread_setname_np((char*)name);
# endif
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
		pthread_set_name_np(pthread_self(), name);
#elif defined(__NetBSD__)
		pthread_setname_np(pthread_self(), "%s", (void *)name);
#elif !defined(__gnu_hurd__)
	#if defined(_MSC_VER)
		THREADNAME_INFO info;
		info.dwType = 0x1000;
		info.szName = name;
		info.dwThreadID = -1;
		info.dwFlags = 0;
		#pragma warning(push)
		#pragma warning(disable: 6320 6322)
		__try {
			RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
		#pragma warning(pop)
	#else
		pthread_setname_np(pthread_self(), name);
	#endif
#endif
	}

namespace net
{
#ifdef _WIN32
	int GetMTUWindowsIpv4 (sockaddr_in inputAddress, int fallback)
	{
		typedef const char *(* IPN)(int af, const void *src, char *dst, socklen_t size);
		IPN inetntop = (IPN)(void*)GetProcAddress (GetModuleHandle ("ws2_32.dll"), "InetNtop");
		if (!inetntop) inetntop = inet_ntop_xp; // use own implementation if not found

		ULONG outBufLen = 0;
		PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
		PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
		PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;

		if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen)
			== ERROR_BUFFER_OVERFLOW)
		{
			FREE(pAddresses);
			pAddresses = (IP_ADAPTER_ADDRESSES*) MALLOC(outBufLen);
		}

		DWORD dwRetVal = GetAdaptersAddresses(
			AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen
		);

		if (dwRetVal != NO_ERROR)
		{
			LogPrint(eLogError, "NetIface: GetMTU: Enclosed GetAdaptersAddresses() call has failed");
			FREE(pAddresses);
			return fallback;
		}

		pCurrAddresses = pAddresses;
		while (pCurrAddresses)
		{
			pUnicast = pCurrAddresses->FirstUnicastAddress;
			if (pUnicast == nullptr)
				LogPrint(eLogError, "NetIface: GetMTU: Not a unicast IPv4 address, this is not supported");

			while (pUnicast != nullptr)
			{
				LPSOCKADDR lpAddr = pUnicast->Address.lpSockaddr;
				sockaddr_in* localInterfaceAddress = (sockaddr_in*) lpAddr;
				if (localInterfaceAddress->sin_addr.S_un.S_addr == inputAddress.sin_addr.S_un.S_addr)
				{
					char addr[INET_ADDRSTRLEN];
					inetntop(AF_INET, &(((struct sockaddr_in *)localInterfaceAddress)->sin_addr), addr, INET_ADDRSTRLEN);

					auto result = pCurrAddresses->Mtu;
					FREE(pAddresses);
					pAddresses = nullptr;
					LogPrint(eLogInfo, "NetIface: GetMTU: Using ", result, " bytes for IPv4 address ", addr);
					return result;
				}
				pUnicast = pUnicast->Next;
			}
			pCurrAddresses = pCurrAddresses->Next;
		}

		LogPrint(eLogError, "NetIface: GetMTU: No usable unicast IPv4 addresses found");
		FREE(pAddresses);
		return fallback;
	}

	int GetMTUWindowsIpv6 (sockaddr_in6 inputAddress, int fallback)
	{
		typedef const char *(* IPN)(int af, const void *src, char *dst, socklen_t size);
		IPN inetntop = (IPN)(void*)GetProcAddress (GetModuleHandle ("ws2_32.dll"), "InetNtop");
		if (!inetntop) inetntop = inet_ntop_xp; // use own implementation if not found

		ULONG outBufLen = 0;
		PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
		PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
		PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;

		if (GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen)
			== ERROR_BUFFER_OVERFLOW)
		{
			FREE(pAddresses);
			pAddresses = (IP_ADAPTER_ADDRESSES*) MALLOC(outBufLen);
		}

		DWORD dwRetVal = GetAdaptersAddresses(
			AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen
		);

		if (dwRetVal != NO_ERROR)
		{
			LogPrint(eLogError, "NetIface: GetMTU: Enclosed GetAdaptersAddresses() call has failed");
			FREE(pAddresses);
			return fallback;
		}

		bool found_address = false;
		pCurrAddresses = pAddresses;
		while (pCurrAddresses)
		{
			pUnicast = pCurrAddresses->FirstUnicastAddress;
			if (pUnicast == nullptr)
				LogPrint(eLogError, "NetIface: GetMTU: Not a unicast IPv6 address, this is not supported");

			while (pUnicast != nullptr)
			{
				LPSOCKADDR lpAddr = pUnicast->Address.lpSockaddr;
				sockaddr_in6 *localInterfaceAddress = (sockaddr_in6*) lpAddr;

				for (int j = 0; j != 8; ++j)
				{
					if (localInterfaceAddress->sin6_addr.u.Word[j] != inputAddress.sin6_addr.u.Word[j])
						break;
					else
						found_address = true;
				}

				if (found_address)
				{
					char addr[INET6_ADDRSTRLEN];
					inetntop(AF_INET6, &(((struct sockaddr_in6 *)localInterfaceAddress)->sin6_addr), addr, INET6_ADDRSTRLEN);

					auto result = pCurrAddresses->Mtu;
					FREE(pAddresses);
					pAddresses = nullptr;
					LogPrint(eLogInfo, "NetIface: GetMTU: Using ", result, " bytes for IPv6 address ", addr);
					return result;
				}
				pUnicast = pUnicast->Next;
			}

			pCurrAddresses = pCurrAddresses->Next;
		}

		LogPrint(eLogError, "NetIface: GetMTU: No usable unicast IPv6 addresses found");
		FREE(pAddresses);
		return fallback;
	}

	int GetMTUWindows (const boost::asio::ip::address& localAddress, int fallback)
	{
#ifdef UNICODE
		string localAddress_temporary = localAddress.to_string();
		wstring localAddressUniversal(localAddress_temporary.begin(), localAddress_temporary.end());
#else
		std::string localAddressUniversal = localAddress.to_string();
#endif

		typedef int (* IPN)(int af, const char *src, void *dst);
		IPN inetpton = (IPN)(void*)GetProcAddress (GetModuleHandle ("ws2_32.dll"), "InetPton");
		if (!inetpton) inetpton = inet_pton_xp; // use own implementation if not found

		if (localAddress.is_v4())
		{
			sockaddr_in inputAddress;
			inetpton(AF_INET, localAddressUniversal.c_str(), &(inputAddress.sin_addr));
			return GetMTUWindowsIpv4(inputAddress, fallback);
		}
		else if (localAddress.is_v6())
		{
			sockaddr_in6 inputAddress;
			inetpton(AF_INET6, localAddressUniversal.c_str(), &(inputAddress.sin6_addr));
			return GetMTUWindowsIpv6(inputAddress, fallback);
		}
		else
		{
			LogPrint(eLogError, "NetIface: GetMTU: Address family is not supported");
			return fallback;
		}
	}
#else // assume unix
	int GetMTUUnix (const boost::asio::ip::address& localAddress, int fallback)
	{
		ifaddrs* ifaddr, *ifa = nullptr;
		if (getifaddrs(&ifaddr) == -1)
		{
			LogPrint(eLogError, "NetIface: Can't call getifaddrs(): ", strerror(errno));
			return fallback;
		}

		int family = 0;
		// look for interface matching local address
		for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
		{
			if (!ifa->ifa_addr)
				continue;

			family = ifa->ifa_addr->sa_family;
			if (family == AF_INET && localAddress.is_v4())
			{
				sockaddr_in* sa = (sockaddr_in*) ifa->ifa_addr;
				if (!memcmp(&sa->sin_addr, localAddress.to_v4().to_bytes().data(), 4))
					break; // address matches
			}
			else if (family == AF_INET6 && localAddress.is_v6())
			{
				sockaddr_in6* sa = (sockaddr_in6*) ifa->ifa_addr;
				if (!memcmp(&sa->sin6_addr, localAddress.to_v6().to_bytes().data(), 16))
					break; // address matches
			}
		}
		int mtu = fallback;
		if (ifa && family)
		{ // interface found?
			int fd = socket(family, SOCK_DGRAM, 0);
			if (fd > 0)
			{
				ifreq ifr;
				strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1); // set interface for query
				if (ioctl(fd, SIOCGIFMTU, &ifr) >= 0)
					mtu = ifr.ifr_mtu; // MTU
				else
					LogPrint (eLogError, "NetIface: Failed to run ioctl: ", strerror(errno));
				close(fd);
			}
			else
				LogPrint(eLogError, "NetIface: Failed to create datagram socket");
		}
		else
			LogPrint(eLogWarning, "NetIface: Interface for local address", localAddress.to_string(), " not found");
		freeifaddrs(ifaddr);

		return mtu;
	}
#endif // _WIN32

	int GetMTU (const boost::asio::ip::address& localAddress)
	{
		int fallback = localAddress.is_v6 () ? 1280 : 620; // fallback MTU

#ifdef _WIN32
		return GetMTUWindows(localAddress, fallback);
#else
		return GetMTUUnix(localAddress, fallback);
#endif
		return fallback;
	}

	const boost::asio::ip::address GetInterfaceAddress (const std::string & ifname, bool ipv6)
	{
#ifdef _WIN32
		LogPrint(eLogError, "NetIface: Cannot get address by interface name, not implemented on WIN32");
		if (ipv6)
			return boost::asio::ip::address::from_string("::1");
		else
			return boost::asio::ip::address::from_string("127.0.0.1");
#else
		int af = (ipv6 ? AF_INET6 : AF_INET);
		ifaddrs *addrs;
		try
		{
			if (!getifaddrs(&addrs))
			{
				for (auto cur = addrs; cur; cur = cur->ifa_next)
				{
					std::string cur_ifname(cur->ifa_name);
					if (cur_ifname == ifname && cur->ifa_addr && cur->ifa_addr->sa_family == af)
					{
						// match
						char addr[INET6_ADDRSTRLEN];
						memset (addr, 0, INET6_ADDRSTRLEN);
						if (af == AF_INET)
							inet_ntop(af, &((sockaddr_in *)cur->ifa_addr)->sin_addr, addr, INET6_ADDRSTRLEN);
						else
							inet_ntop(af, &((sockaddr_in6 *)cur->ifa_addr)->sin6_addr, addr, INET6_ADDRSTRLEN);
						freeifaddrs(addrs);
						std::string cur_ifaddr(addr);
						return boost::asio::ip::address::from_string(cur_ifaddr);
					}
				}
			}
		}
		catch (std::exception& ex)
		{
			LogPrint(eLogError, "NetIface: Exception while searching address using ifaddr: ", ex.what());
		}

		if (addrs) freeifaddrs(addrs);
		std::string fallback;
		if (ipv6)
		{
			fallback = "::1";
			LogPrint(eLogWarning, "NetIface: Cannot find IPv6 address for interface ", ifname);
		} else {
			fallback = "127.0.0.1";
			LogPrint(eLogWarning, "NetIface: Cannot find IPv4 address for interface ", ifname);
		}
		return boost::asio::ip::address::from_string(fallback);
#endif
	}

	int GetMaxMTU (const boost::asio::ip::address_v6& localAddress)
	{
		uint32_t prefix = bufbe32toh (localAddress.to_bytes ().data ());
		switch (prefix)
		{
			case 0x20010470:
			case 0x260070ff:
			// Hurricane Electric
				return 1480;
			break;
			case 0x2a06a003:
			case 0x2a06a004:
			case 0x2a06a005:
			// route48
				return 1420;
			break;
			default: ;
		}
		return 1500;
	}

	static bool IsYggdrasilAddress (const uint8_t addr[16])
	{
		return addr[0] == 0x02 || addr[0] == 0x03;
	}

	bool IsYggdrasilAddress (const boost::asio::ip::address& addr)
	{
		if (!addr.is_v6 ()) return false;
		return IsYggdrasilAddress (addr.to_v6 ().to_bytes ().data ());
	}

	bool IsPortInReservedRange (const uint16_t port) noexcept
	{
		// https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers (Feb. 3, 2023) + Tor browser (9150)
		static const std::unordered_set<uint16_t> reservedPorts{
			9119,9150,9306,9312,9389,9418,9535,9536,9695,
			9800,9899,10000,10050,10051,10110,10212,
			10933,11001,11112,11235,11371,12222,12223,
			13075,13400,13720,13721,13724,13782,13783,
			13785,13786,15345,17224,17225,17500,18104,
			19788,19812,19813,19814,19999,20000,24465,
			24554,26000,27000,27001,27002,27003,27004,
			27005,27006,27007,27008,27009,28000};

		return (reservedPorts.find(port) != reservedPorts.end());
	}

	boost::asio::ip::address_v6 GetYggdrasilAddress ()
	{
#if defined(_WIN32)
		ULONG outBufLen = 0;
		PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
		PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
		PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;

		if (GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen)
			== ERROR_BUFFER_OVERFLOW)
		{
			FREE(pAddresses);
			pAddresses = (IP_ADAPTER_ADDRESSES*) MALLOC(outBufLen);
		}

		DWORD dwRetVal = GetAdaptersAddresses(
			AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen
		);

		if (dwRetVal != NO_ERROR)
		{
			LogPrint(eLogError, "NetIface: GetYggdrasilAddress(): enclosed GetAdaptersAddresses() call has failed");
			FREE(pAddresses);
			return boost::asio::ip::address_v6 ();
		}

		pCurrAddresses = pAddresses;
		while (pCurrAddresses)
		{
			pUnicast = pCurrAddresses->FirstUnicastAddress;

			while (pUnicast != nullptr)
			{
				LPSOCKADDR lpAddr = pUnicast->Address.lpSockaddr;
				sockaddr_in6 *localInterfaceAddress = (sockaddr_in6*) lpAddr;
				if (IsYggdrasilAddress(localInterfaceAddress->sin6_addr.u.Byte)) {
					boost::asio::ip::address_v6::bytes_type bytes;
					memcpy (bytes.data (), &localInterfaceAddress->sin6_addr.u.Byte, 16);
					FREE(pAddresses);
					return boost::asio::ip::address_v6 (bytes);
				}
				pUnicast = pUnicast->Next;
			}
			pCurrAddresses = pCurrAddresses->Next;
		}
		LogPrint(eLogWarning, "NetIface: Interface with Yggdrasil network address not found");
		FREE(pAddresses);
		return boost::asio::ip::address_v6 ();
#else
		ifaddrs *addrs;
		try
		{
			if (!getifaddrs(&addrs))
			{
				for (auto cur = addrs; cur; cur = cur->ifa_next)
				{
					if (cur->ifa_addr && cur->ifa_addr->sa_family == AF_INET6)
					{
						sockaddr_in6* sa = (sockaddr_in6*)cur->ifa_addr;
						if (IsYggdrasilAddress(sa->sin6_addr.s6_addr))
						{
							boost::asio::ip::address_v6::bytes_type bytes;
							memcpy (bytes.data (), &sa->sin6_addr, 16);
							freeifaddrs(addrs);
							return boost::asio::ip::address_v6 (bytes);
						}
					}
				}
			}
		}
		catch (std::exception& ex)
		{
			LogPrint(eLogError, "NetIface: Exception while searching Yggdrasill address using ifaddr: ", ex.what());
		}
		LogPrint(eLogWarning, "NetIface: Interface with Yggdrasil network address not found");
		if (addrs) freeifaddrs(addrs);
		return boost::asio::ip::address_v6 ();
#endif
	}

	bool IsLocalAddress (const boost::asio::ip::address& addr)
	{
		auto mtu = // TODO: implement better
#ifdef _WIN32
		GetMTUWindows(addr, 0);
#else
		GetMTUUnix(addr, 0);
#endif
		return mtu > 0;
	}

	bool IsInReservedRange (const boost::asio::ip::address& host)
	{
		// https://en.wikipedia.org/wiki/Reserved_IP_addresses
		if (host.is_unspecified ()) return false;
		if (host.is_v4())
		{
			static const std::vector< std::pair<uint32_t, uint32_t> > reservedIPv4Ranges {
				address_pair_v4("0.0.0.0",      "0.255.255.255"),
				address_pair_v4("10.0.0.0",     "10.255.255.255"),
				address_pair_v4("100.64.0.0",   "100.127.255.255"),
				address_pair_v4("127.0.0.0",    "127.255.255.255"),
				address_pair_v4("169.254.0.0",  "169.254.255.255"),
				address_pair_v4("172.16.0.0",   "172.31.255.255"),
				address_pair_v4("192.0.0.0",    "192.0.0.255"),
				address_pair_v4("192.0.2.0",    "192.0.2.255"),
				address_pair_v4("192.88.99.0",  "192.88.99.255"),
				address_pair_v4("192.168.0.0",  "192.168.255.255"),
				address_pair_v4("198.18.0.0",   "192.19.255.255"),
				address_pair_v4("198.51.100.0", "198.51.100.255"),
				address_pair_v4("203.0.113.0",  "203.0.113.255"),
				address_pair_v4("224.0.0.0",    "255.255.255.255")
			};

			uint32_t ipv4_address = host.to_v4 ().to_ulong ();
			for (const auto& it : reservedIPv4Ranges) {
				if (ipv4_address >= it.first && ipv4_address <= it.second)
					return true;
			}
		}
		if (host.is_v6())
		{
			static const std::vector< std::pair<boost::asio::ip::address_v6::bytes_type, boost::asio::ip::address_v6::bytes_type> > reservedIPv6Ranges {
				address_pair_v6("64:ff9b::",  "64:ff9b:ffff:ffff:ffff:ffff:ffff:ffff"),  // NAT64
				address_pair_v6("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
				address_pair_v6("fc00::",     "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
				address_pair_v6("fe80::",     "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
				address_pair_v6("ff00::",     "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
				address_pair_v6("::",         "::"),
				address_pair_v6("::1",        "::1")
			};

			boost::asio::ip::address_v6::bytes_type ipv6_address = host.to_v6 ().to_bytes ();
			for (const auto& it : reservedIPv6Ranges) {
				if (ipv6_address >= it.first && ipv6_address <= it.second)
					return true;
			}
			if (IsYggdrasilAddress (ipv6_address.data ())) // yggdrasil?
				return true;
		}
		return false;
	}
} // net
} // util
} // i2p
