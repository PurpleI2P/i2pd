#ifndef WIN_32_NETSTATE_H__
#define WIN_32_NETSTATE_H__

#if WINVER != 0x0501 // supported since Vista
#include <netlistmgr.h>
#include <ocidl.h>
#include "Log.h"
#include "Transports.h"

class CNetworkListManagerEvent : public INetworkListManagerEvents
{
public:
	CNetworkListManagerEvent() : m_ref(1) { }
	~CNetworkListManagerEvent() { }

	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject)
	{
		HRESULT Result = S_OK;
		if (IsEqualIID(riid, IID_IUnknown)) {
			*ppvObject = (IUnknown *)this;
		} else if (IsEqualIID(riid ,IID_INetworkListManagerEvents)) {
			*ppvObject = (INetworkListManagerEvents *)this;
		} else {
			Result = E_NOINTERFACE;
		}

		return Result;
	}

	ULONG STDMETHODCALLTYPE AddRef()
	{
		return (ULONG)InterlockedIncrement(&m_ref);
	}

	ULONG STDMETHODCALLTYPE Release()
	{
		LONG Result = InterlockedDecrement(&m_ref);
		if (Result == 0)
			delete this;
		return (ULONG)Result;
	}

	virtual HRESULT STDMETHODCALLTYPE ConnectivityChanged(NLM_CONNECTIVITY newConnectivity)
	{
		if (newConnectivity == NLM_CONNECTIVITY_DISCONNECTED) {
			i2p::transport::transports.SetOnline (false);
			LogPrint(eLogInfo, "NetState: disconnected from network");
		}

		if (((int)newConnectivity & (int)NLM_CONNECTIVITY_IPV4_INTERNET) != 0) {
			i2p::transport::transports.SetOnline (true);
			LogPrint(eLogInfo, "NetState: connected to internet with IPv4 capability");
		}

		if (((int)newConnectivity & (int)NLM_CONNECTIVITY_IPV6_INTERNET) != 0) {
			i2p::transport::transports.SetOnline (true);
			LogPrint(eLogInfo, "NetState: connected to internet with IPv6 capability");
		}

		if (
			(((int)newConnectivity & (int)NLM_CONNECTIVITY_IPV4_INTERNET) == 0) &&
			(((int)newConnectivity & (int)NLM_CONNECTIVITY_IPV6_INTERNET) == 0)
		) {
			i2p::transport::transports.SetOnline (false);
			LogPrint(eLogInfo, "NetState: connected without internet access");
		}

		return S_OK;
	}

private:

	LONG m_ref;
};

void SubscribeToEvents();
void UnSubscribeFromEvents();

#else // WINVER == 0x0501

void SubscribeToEvents() { }
void UnSubscribeFromEvents() { }

#endif // WINVER
#endif