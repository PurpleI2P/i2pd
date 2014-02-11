#include "Win32Service.h"
#include <assert.h>
#include <strsafe.h>
#include <windows.h>

#include "Transports.h"
#include "NTCPSession.h"
#include "Tunnel.h"
#include "NetDb.h"
#include "util.h"

I2PService *I2PService::s_service = NULL;


BOOL I2PService::Run(I2PService &service)
{
	s_service = &service;

	SERVICE_TABLE_ENTRY serviceTable[] =
	{
		{ service.m_name, ServiceMain },
		{ NULL, NULL }
	};

	return StartServiceCtrlDispatcher(serviceTable);
}


void WINAPI I2PService::ServiceMain(DWORD dwArgc, PSTR *pszArgv)
{
	assert(s_service != NULL);

	s_service->m_statusHandle = RegisterServiceCtrlHandler(
		s_service->m_name, ServiceCtrlHandler);
	if (s_service->m_statusHandle == NULL)
	{
		throw GetLastError();
	}

	s_service->Start(dwArgc, pszArgv);
}


void WINAPI I2PService::ServiceCtrlHandler(DWORD dwCtrl)
{
	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP: s_service->Stop(); break;
	case SERVICE_CONTROL_PAUSE: s_service->Pause(); break;
	case SERVICE_CONTROL_CONTINUE: s_service->Continue(); break;
	case SERVICE_CONTROL_SHUTDOWN: s_service->Shutdown(); break;
	case SERVICE_CONTROL_INTERROGATE: break;
	default: break;
	}
}


I2PService::I2PService(PSTR pszServiceName,
	BOOL fCanStop,
	BOOL fCanShutdown,
	BOOL fCanPauseContinue) : _httpServer(nullptr)
{
	m_name = (pszServiceName == NULL) ? "" : pszServiceName;

	m_statusHandle = NULL;

	m_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

	m_status.dwCurrentState = SERVICE_START_PENDING;

	DWORD dwControlsAccepted = 0;
	if (fCanStop)
		dwControlsAccepted |= SERVICE_ACCEPT_STOP;
	if (fCanShutdown)
		dwControlsAccepted |= SERVICE_ACCEPT_SHUTDOWN;
	if (fCanPauseContinue)
		dwControlsAccepted |= SERVICE_ACCEPT_PAUSE_CONTINUE;
	m_status.dwControlsAccepted = dwControlsAccepted;

	m_status.dwWin32ExitCode = NO_ERROR;
	m_status.dwServiceSpecificExitCode = 0;
	m_status.dwCheckPoint = 0;
	m_status.dwWaitHint = 0;

	m_fStopping = FALSE;

	// Create a manual-reset event that is not signaled at first to indicate 
	// the stopped signal of the service.
	m_hStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_hStoppedEvent == NULL)
	{
		throw GetLastError();
	}
}


I2PService::~I2PService(void)
{
	if (m_hStoppedEvent)
	{
		CloseHandle(m_hStoppedEvent);
		m_hStoppedEvent = NULL;
	}
}


void I2PService::Start(DWORD dwArgc, PSTR *pszArgv)
{
	try
	{
		SetServiceStatus(SERVICE_START_PENDING);

		OnStart(dwArgc, pszArgv);

		SetServiceStatus(SERVICE_RUNNING);
	}
	catch (DWORD dwError)
	{
		WriteErrorLogEntry("Service Start", dwError);

		SetServiceStatus(SERVICE_STOPPED, dwError);
	}
	catch (...)
	{
		WriteEventLogEntry("Service failed to start.", EVENTLOG_ERROR_TYPE);

		SetServiceStatus(SERVICE_STOPPED);
	}
}


void I2PService::OnStart(DWORD dwArgc, PSTR *pszArgv)
{
	WriteEventLogEntry("CppWindowsService in OnStart",
		EVENTLOG_INFORMATION_TYPE);

	i2p::util::config::OptionParser(dwArgc, pszArgv);
	i2p::util::filesystem::ReadConfigFile(i2p::util::config::mapArgs, i2p::util::config::mapMultiArgs);
	i2p::context.OverrideNTCPAddress(i2p::util::config::GetCharArg("-host", "127.0.0.1"),
		i2p::util::config::GetArg("-port", 17070));

	_httpServer = new i2p::util::HTTPServer(i2p::util::config::GetArg("-httpport", 7070));
	_httpServer->Start();
	WriteEventLogEntry("HTTPServer started",
		EVENTLOG_INFORMATION_TYPE);
	i2p::data::netdb.Start();
	WriteEventLogEntry("NetDB started",
		EVENTLOG_INFORMATION_TYPE);
	i2p::transports.Start();
	WriteEventLogEntry("Transports started",
		EVENTLOG_INFORMATION_TYPE);
	i2p::tunnel::tunnels.Start();
	WriteEventLogEntry("Tunnels started",
		EVENTLOG_INFORMATION_TYPE);
	_worker = new std::thread(std::bind(&I2PService::WorkerThread, this));
}


void I2PService::WorkerThread()
{
	while (!m_fStopping)
	{
		::Sleep(1000);  // Simulate some lengthy operations.
	}

	// Signal the stopped event.
	SetEvent(m_hStoppedEvent);
}


void I2PService::Stop()
{
	DWORD dwOriginalState = m_status.dwCurrentState;
	try
	{
		SetServiceStatus(SERVICE_STOP_PENDING);

		OnStop();

		SetServiceStatus(SERVICE_STOPPED);
	}
	catch (DWORD dwError)
	{
		WriteErrorLogEntry("Service Stop", dwError);

		SetServiceStatus(dwOriginalState);
	}
	catch (...)
	{
		WriteEventLogEntry("Service failed to stop.", EVENTLOG_ERROR_TYPE);

		SetServiceStatus(dwOriginalState);
	}
}


void I2PService::OnStop()
{
	// Log a service stop message to the Application log.
	WriteEventLogEntry("CppWindowsService in OnStop",
		EVENTLOG_INFORMATION_TYPE);

	i2p::tunnel::tunnels.Stop();
	WriteEventLogEntry("Tunnels stoped",
		EVENTLOG_INFORMATION_TYPE);
	i2p::transports.Stop();
	WriteEventLogEntry("Transports stoped",
		EVENTLOG_INFORMATION_TYPE);
	i2p::data::netdb.Stop();
	WriteEventLogEntry("NetDB stoped",
		EVENTLOG_INFORMATION_TYPE);
	_httpServer->Stop();
	WriteEventLogEntry("HTTPServer stoped",
		EVENTLOG_INFORMATION_TYPE);
	delete _httpServer;

	m_fStopping = TRUE;
	if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
	{
		throw GetLastError();
	}
	_worker->join();
	delete _worker;
}


void I2PService::Pause()
{
	try
	{
		SetServiceStatus(SERVICE_PAUSE_PENDING);

		OnPause();

		SetServiceStatus(SERVICE_PAUSED);
	}
	catch (DWORD dwError)
	{
		WriteErrorLogEntry("Service Pause", dwError);

		SetServiceStatus(SERVICE_RUNNING);
	}
	catch (...)
	{
		WriteEventLogEntry("Service failed to pause.", EVENTLOG_ERROR_TYPE);

		SetServiceStatus(SERVICE_RUNNING);
	}
}


void I2PService::OnPause()
{
}


void I2PService::Continue()
{
	try
	{
		SetServiceStatus(SERVICE_CONTINUE_PENDING);

		OnContinue();

		SetServiceStatus(SERVICE_RUNNING);
	}
	catch (DWORD dwError)
	{
		WriteErrorLogEntry("Service Continue", dwError);

		SetServiceStatus(SERVICE_PAUSED);
	}
	catch (...)
	{
		WriteEventLogEntry("Service failed to resume.", EVENTLOG_ERROR_TYPE);

		SetServiceStatus(SERVICE_PAUSED);
	}
}


void I2PService::OnContinue()
{
}


void I2PService::Shutdown()
{
	try
	{
		OnShutdown();

		SetServiceStatus(SERVICE_STOPPED);
	}
	catch (DWORD dwError)
	{
		WriteErrorLogEntry("Service Shutdown", dwError);
	}
	catch (...)
	{
		WriteEventLogEntry("Service failed to shut down.", EVENTLOG_ERROR_TYPE);
	}
}


void I2PService::OnShutdown()
{
}


void I2PService::SetServiceStatus(DWORD dwCurrentState,
	DWORD dwWin32ExitCode,
	DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;


	m_status.dwCurrentState = dwCurrentState;
	m_status.dwWin32ExitCode = dwWin32ExitCode;
	m_status.dwWaitHint = dwWaitHint;

	m_status.dwCheckPoint =
		((dwCurrentState == SERVICE_RUNNING) ||
		(dwCurrentState == SERVICE_STOPPED)) ?
		0 : dwCheckPoint++;

	::SetServiceStatus(m_statusHandle, &m_status);
}


void I2PService::WriteEventLogEntry(PSTR pszMessage, WORD wType)
{
	HANDLE hEventSource = NULL;
	LPCSTR lpszStrings[2] = { NULL, NULL };

	hEventSource = RegisterEventSource(NULL, m_name);
	if (hEventSource)
	{
		lpszStrings[0] = m_name;
		lpszStrings[1] = pszMessage;

		ReportEvent(hEventSource,  // Event log handle
			wType,                 // Event type
			0,                     // Event category
			0,                     // Event identifier
			NULL,                  // No security identifier
			2,                     // Size of lpszStrings array
			0,                     // No binary data
			lpszStrings,           // Array of strings
			NULL                   // No binary data
			);

		DeregisterEventSource(hEventSource);
	}
}


void I2PService::WriteErrorLogEntry(PSTR pszFunction, DWORD dwError)
{
	char szMessage[260];
	StringCchPrintf(szMessage, ARRAYSIZE(szMessage),
		"%s failed w/err 0x%08lx", pszFunction, dwError);
	WriteEventLogEntry(szMessage, EVENTLOG_ERROR_TYPE);
}

//*****************************************************************************

void FreeHandles(SC_HANDLE schSCManager, SC_HANDLE schService)
{
	if (schSCManager)
	{
		CloseServiceHandle(schSCManager);
		schSCManager = NULL;
	}
	if (schService)
	{
		CloseServiceHandle(schService);
		schService = NULL;
	}
}

void InstallService(PSTR pszServiceName,
	PSTR pszDisplayName,
	DWORD dwStartType,
	PSTR pszDependencies,
	PSTR pszAccount,
	PSTR pszPassword)
{
	char szPath[MAX_PATH];
	SC_HANDLE schSCManager = NULL;
	SC_HANDLE schService = NULL;

	if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)) == 0)
	{
		printf("GetModuleFileName failed w/err 0x%08lx\n", GetLastError());
		FreeHandles(schSCManager, schService);
		return;
	}

	// Open the local default service control manager database
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT |
		SC_MANAGER_CREATE_SERVICE);
	if (schSCManager == NULL)
	{
		printf("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
		FreeHandles(schSCManager, schService);
		return;
	}

	// Install the service into SCM by calling CreateService
	schService = CreateService(
		schSCManager,                   // SCManager database
		pszServiceName,                 // Name of service
		pszDisplayName,                 // Name to display
		SERVICE_QUERY_STATUS,           // Desired access
		SERVICE_WIN32_OWN_PROCESS,      // Service type
		dwStartType,                    // Service start type
		SERVICE_ERROR_NORMAL,           // Error control type
		szPath,                         // Service's binary
		NULL,                           // No load ordering group
		NULL,                           // No tag identifier
		pszDependencies,                // Dependencies
		pszAccount,                     // Service running account
		pszPassword                     // Password of the account
		);
	if (schService == NULL)
	{
		printf("CreateService failed w/err 0x%08lx\n", GetLastError());
		FreeHandles(schSCManager, schService);
		return;
	}

	printf("%s is installed.\n", pszServiceName);

	// Centralized cleanup for all allocated resources.
	FreeHandles(schSCManager, schService);
}

void UninstallService(PSTR pszServiceName)
{
	SC_HANDLE schSCManager = NULL;
	SC_HANDLE schService = NULL;
	SERVICE_STATUS ssSvcStatus = {};

	// Open the local default service control manager database
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (schSCManager == NULL)
	{
		printf("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
		FreeHandles(schSCManager, schService);
		return;
	}

	// Open the service with delete, stop, and query status permissions
	schService = OpenService(schSCManager, pszServiceName, SERVICE_STOP |
		SERVICE_QUERY_STATUS | DELETE);
	if (schService == NULL)
	{
		printf("OpenService failed w/err 0x%08lx\n", GetLastError());
		FreeHandles(schSCManager, schService);
		return;
	}

	// Try to stop the service
	if (ControlService(schService, SERVICE_CONTROL_STOP, &ssSvcStatus))
	{
		printf("Stopping %s.", pszServiceName);
		Sleep(1000);

		while (QueryServiceStatus(schService, &ssSvcStatus))
		{
			if (ssSvcStatus.dwCurrentState == SERVICE_STOP_PENDING)
			{
				printf(".");
				Sleep(1000);
			}
			else break;
		}

		if (ssSvcStatus.dwCurrentState == SERVICE_STOPPED)
		{
			printf("\n%s is stopped.\n", pszServiceName);
		}
		else
		{
			printf("\n%s failed to stop.\n", pszServiceName);
		}
	}

	// Now remove the service by calling DeleteService.
	if (!DeleteService(schService))
	{
		printf("DeleteService failed w/err 0x%08lx\n", GetLastError());
		FreeHandles(schSCManager, schService);
		return;
	}

	printf("%s is removed.\n", pszServiceName);

	// Centralized cleanup for all allocated resources.
	FreeHandles(schSCManager, schService);
}