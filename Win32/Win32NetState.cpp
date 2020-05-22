/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#if WINVER != 0x0501 // supported since Vista
#include "Win32NetState.h"
#include <windows.h>
#include "Log.h"

IUnknown *pUnknown = nullptr;
INetworkListManager *pNetworkListManager = nullptr;
IConnectionPointContainer *pCPContainer = nullptr;
IConnectionPoint *pConnectPoint = nullptr;
DWORD Cookie = 0;

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
			VARIANT_BOOL IsConnect = VARIANT_FALSE;
			Result = pNetworkListManager->IsConnectedToInternet(&IsConnect);
			if (SUCCEEDED(Result)) {
				i2p::transport::transports.SetOnline (true);
				LogPrint(eLogInfo, "NetState: current state: ", IsConnect == VARIANT_TRUE ? "connected" : "disconnected");
			}

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
					else
						LogPrint(eLogError, "NetState: Unable to subscribe to NetworkListManagerEvent messages");
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
	try
	{
		if (pConnectPoint) {
			pConnectPoint->Unadvise(Cookie);
			pConnectPoint->Release();
		}

		if (pCPContainer)
			pCPContainer->Release();

		if (pNetworkListManager)
			pNetworkListManager->Release();

		if (pUnknown)
			pUnknown->Release();

		CoUninitialize();
	}
	catch (std::exception& ex)
	{
		LogPrint (eLogError, "NetState: received exception: ", ex.what ());
	}
}

#endif // WINVER
