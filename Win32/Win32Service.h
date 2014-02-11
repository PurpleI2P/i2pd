#ifndef WIN_32_SERVICE_H__
#define WIN_32_SERVICE_H__

#include "HTTPServer.h"
#include <thread>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

class I2PService
{
public:

	I2PService(PSTR pszServiceName,
		BOOL fCanStop = TRUE,
		BOOL fCanShutdown = TRUE,
		BOOL fCanPauseContinue = FALSE);

	virtual ~I2PService(void);

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
	void WriteEventLogEntry(PSTR pszMessage, WORD wType);
	void WriteErrorLogEntry(PSTR pszFunction,
		DWORD dwError = GetLastError());

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
	i2p::util::HTTPServer* _httpServer;
	std::thread* _worker;
};

void InstallService(PSTR pszServiceName,
	PSTR pszDisplayName,
	DWORD dwStartType,
	PSTR pszDependencies,
	PSTR pszAccount,
	PSTR pszPassword);

void UninstallService(PSTR pszServiceName);

#endif // WIN_32_SERVICE_H__