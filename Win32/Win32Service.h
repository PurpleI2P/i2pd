/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef WIN_32_SERVICE_H__
#define WIN_32_SERVICE_H__

#include <thread>
#include <windows.h>

#ifdef _WIN32
// Internal name of the service
#define SERVICE_NAME             "i2pdService"

// Displayed name of the service
#define SERVICE_DISPLAY_NAME     "i2pd router service"

// Service start options.
#define SERVICE_START_TYPE       SERVICE_DEMAND_START

// List of service dependencies - "dep1\0dep2\0\0"
#define SERVICE_DEPENDENCIES     ""

// The name of the account under which the service should run
#define SERVICE_ACCOUNT          "NT AUTHORITY\\LocalService"

// The password to the service account name
#define SERVICE_PASSWORD         NULL
#endif

class I2PService
{
	public:

		I2PService(PSTR pszServiceName,
			BOOL fCanStop = TRUE,
			BOOL fCanShutdown = TRUE,
			BOOL fCanPauseContinue = FALSE);

		virtual ~I2PService(void);

		static BOOL isService();
		static BOOL Run(I2PService &service);
		void Stop();

	protected:

		virtual void OnStart(DWORD dwArgc, PSTR *pszArgv);
		virtual void OnStop();
		virtual void OnPause();
		virtual void OnContinue();
		virtual void OnShutdown();
		void SetServiceStatus(DWORD dwCurrentState,
			DWORD dwWin32ExitCode = NO_ERROR,
			DWORD dwWaitHint = 0);

	private:

		static void WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv);
		static void WINAPI ServiceCtrlHandler(DWORD dwCtrl);
		void WorkerThread();
		void Start(DWORD dwArgc, PSTR *pszArgv);
		void Pause();
		void Continue();
		void Shutdown();
		static I2PService* s_service;
		PSTR m_name;
		SERVICE_STATUS m_status;
		SERVICE_STATUS_HANDLE m_statusHandle;

		BOOL m_fStopping;
		HANDLE m_hStoppedEvent;

		std::thread* _worker;
};

void InstallService(
	PCSTR pszServiceName,
	PCSTR pszDisplayName,
	DWORD dwStartType,
	PCSTR pszDependencies,
	PCSTR pszAccount,
	PCSTR pszPassword
);

void UninstallService(PCSTR pszServiceName);

#endif // WIN_32_SERVICE_H__
