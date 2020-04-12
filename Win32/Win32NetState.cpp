#if WINVER != 0x0501 // supported since Vista
#include "Win32NetState.h"
#include <windows.h>
#include "Log.h"

IUnknown *pUnknown = NULL;
INetworkListManager *pNetworkListManager = NULL;
IConnectionPointContainer *pCPContainer = NULL;
DWORD Cookie = 0;
IConnectionPoint *pConnectPoint = NULL;

void SubscribeToEvents()
{
	LogPrint(eLogInfo, "NetState: Trying to subscribe to NetworkListManagerEvents");
	CoInitialize(NULL);

	HRESULT Result = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, IID_IUnknown, (void **)&pUnknown);
	if (SUCCEEDED(Result))
	{
		Result = pUnknown->QueryInterface(IID_INetworkListManager, (void **)&pNetworkListManager);
		if (SUCCEEDED(Result))
		{
			/* VARIANT_BOOL IsConnect = VARIANT_FALSE;
			Result = pNetworkListManager->IsConnectedToInternet(&IsConnect);
			if (SUCCEEDED(Result))
				LogPrint(eLogInfo, "NetState: IsConnect Result:", IsConnect == VARIANT_TRUE ? "TRUE" : "FALSE"); */

			Result = pNetworkListManager->QueryInterface(IID_IConnectionPointContainer, (void **)&pCPContainer);
			if (SUCCEEDED(Result))
			{
				Result = pCPContainer->FindConnectionPoint(IID_INetworkListManagerEvents, &pConnectPoint);
				if(SUCCEEDED(Result))
				{
					CNetworkListManagerEvent *NetEvent = new CNetworkListManagerEvent;
					Result = pConnectPoint->Advise((IUnknown *)NetEvent, &Cookie);
					if (SUCCEEDED(Result))
						LogPrint(eLogInfo, "NetState: Successfully subscribed to NetworkListManagerEvent messages");
						} else
					LogPrint(eLogError, "NetState: Unable to find interface connection point");
			} else
				LogPrint(eLogError, "NetState: Unable to query NetworkListManager interface");
		} else
			LogPrint(eLogError, "NetState: Unable to query global interface");
	} else
		LogPrint(eLogError, "NetState: Unable to create INetworkListManager interface");
}

void UnSubscribeFromEvents()
{
	// TODO - DETECT EVERY STAGE STATE and call functions depending it !!!
	pConnectPoint->Unadvise(Cookie);
	pConnectPoint->Release();
	pCPContainer->Release();
	pNetworkListManager->Release();
	pUnknown->Release();
	CoUninitialize();
}

#endif // WINVER
