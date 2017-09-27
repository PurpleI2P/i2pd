#include <string.h>
#include <windows.h>
#include <shellapi.h>
#include "ClientContext.h"
#include "Config.h"
#include "NetDb.hpp"
#include "RouterContext.h"
#include "Transports.h"
#include "Tunnel.h"
#include "version.h"
#include "resource.h"
#include "Daemon.h"
#include "Win32App.h"
#include <stdio.h>

#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf
#endif

#define ID_ABOUT 2000
#define ID_EXIT 2001
#define ID_CONSOLE 2002
#define ID_APP 2003
#define ID_GRACEFUL_SHUTDOWN 2004
#define ID_STOP_GRACEFUL_SHUTDOWN 2005
#define ID_RELOAD 2006

#define ID_TRAY_ICON 2050
#define WM_TRAYICON (WM_USER + 1)

#define IDT_GRACEFUL_SHUTDOWN_TIMER 2100
#define FRAME_UPDATE_TIMER 2101

namespace i2p
{
namespace win32
{
	static void ShowPopupMenu (HWND hWnd, POINT *curpos, int wDefaultItem)
	{
		HMENU hPopup = CreatePopupMenu();
		InsertMenu (hPopup, -1, MF_BYPOSITION | MF_STRING, ID_CONSOLE, "Open &console");
		InsertMenu (hPopup, -1, MF_BYPOSITION | MF_STRING, ID_APP, "Show app");
		InsertMenu (hPopup, -1, MF_BYPOSITION | MF_STRING, ID_ABOUT, "&About...");
		InsertMenu (hPopup, -1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
		InsertMenu (hPopup, -1, MF_BYPOSITION | MF_STRING, ID_RELOAD, "&Reload configs");
		if (!i2p::util::DaemonWin32::Instance ().isGraceful)
			InsertMenu (hPopup, -1, MF_BYPOSITION | MF_STRING, ID_GRACEFUL_SHUTDOWN, "&Graceful shutdown");
		else
			InsertMenu (hPopup, -1, MF_BYPOSITION | MF_STRING, ID_STOP_GRACEFUL_SHUTDOWN, "&Stop graceful shutdown");
		InsertMenu (hPopup, -1, MF_BYPOSITION | MF_STRING, ID_EXIT, "E&xit");
		SetMenuDefaultItem (hPopup, ID_CONSOLE, FALSE);
		SendMessage (hWnd, WM_INITMENUPOPUP, (WPARAM)hPopup, 0);

		POINT p;
		if (!curpos)
		{
			GetCursorPos (&p);
			curpos = &p;
		}

		WORD cmd = TrackPopupMenu (hPopup, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, curpos->x, curpos->y, 0, hWnd, NULL);
		SendMessage (hWnd, WM_COMMAND, cmd, 0);

		DestroyMenu(hPopup);
	}

	static void AddTrayIcon (HWND hWnd)
	{
		NOTIFYICONDATA nid;
		memset(&nid, 0, sizeof(nid));
		nid.cbSize = sizeof(nid);
		nid.hWnd = hWnd;
		nid.uID = ID_TRAY_ICON;
		nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
		nid.uCallbackMessage = WM_TRAYICON;
		nid.hIcon = LoadIcon (GetModuleHandle(NULL), MAKEINTRESOURCE (MAINICON));
		strcpy (nid.szTip, "i2pd");
		strcpy (nid.szInfo, "i2pd is starting");
		Shell_NotifyIcon(NIM_ADD, &nid );
	}

	static void RemoveTrayIcon (HWND hWnd)
	{
		NOTIFYICONDATA nid;
		nid.hWnd = hWnd;
		nid.uID = ID_TRAY_ICON;
		Shell_NotifyIcon (NIM_DELETE, &nid);
	}

	static void ShowUptime (std::stringstream& s, int seconds)
	{
		int num;

		if ((num = seconds / 86400) > 0) {
			s << num << " days, ";
			seconds -= num * 86400;
		}
		if ((num = seconds / 3600) > 0) {
			s << num << " hours, ";
			seconds -= num * 3600;
		}
		if ((num = seconds / 60) > 0) {
			s << num << " min, ";
			seconds -= num * 60;
		}
		s << seconds << " seconds\n";
	}

	template <typename size> static void ShowTransfered (std::stringstream& s, size transfer)
	{
		auto bytes = transfer & 0x03ff;
		transfer >>= 10;
		auto kbytes = transfer & 0x03ff;
		transfer >>= 10;
		auto mbytes = transfer & 0x03ff;
		transfer >>= 10;
		auto gbytes = transfer & 0x03ff;

		if (gbytes)
			s << gbytes << " GB, ";
		if (mbytes)
			s << mbytes << " MB, ";
		if (kbytes)
			s << kbytes << " KB, ";
		s << bytes << " Bytes\n";
	}

	static void PrintMainWindowText (std::stringstream& s)
	{
		s << "\n";
		s << "Status: ";
		switch (i2p::context.GetStatus())
		{
			case eRouterStatusOK: s << "OK"; break;
			case eRouterStatusTesting: s << "Testing"; break;
			case eRouterStatusFirewalled: s << "Firewalled"; break;
			case eRouterStatusError:
			{
				switch (i2p::context.GetError())
				{
					case eRouterErrorClockSkew: s << "Clock skew"; break;
					default: s << "Error";
				}
				break;
			}
			default: s << "Unknown";
		}
		s << "; ";
		s << "Success Rate: " << i2p::tunnel::tunnels.GetTunnelCreationSuccessRate() << "%\n";
		s << "Uptime: "; ShowUptime(s, i2p::context.GetUptime ());
		s << "\n";
		s << "Inbound: " << i2p::transport::transports.GetInBandwidth() / 1024 << " KiB/s; ";
		s << "Outbound: " << i2p::transport::transports.GetOutBandwidth() / 1024 << " KiB/s\n";
		s << "Received: "; ShowTransfered (s, i2p::transport::transports.GetTotalReceivedBytes());
		s << "Sent: "; ShowTransfered (s, i2p::transport::transports.GetTotalSentBytes());
		s << "\n";
		s << "Routers: " << i2p::data::netdb.GetNumRouters () << "; ";
		s << "Floodfills: " << i2p::data::netdb.GetNumFloodfills () << "; ";
		s << "LeaseSets: " << i2p::data::netdb.GetNumLeaseSets () << "\n";
		s << "Tunnels: ";
		s << "In: " << i2p::tunnel::tunnels.CountInboundTunnels() << "; ";
		s << "Out: " << i2p::tunnel::tunnels.CountOutboundTunnels() << "; ";
		s << "Transit: " << i2p::tunnel::tunnels.CountTransitTunnels() << "\n";
		s << "\n";
	}

	static LRESULT CALLBACK WndProc (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
			case WM_CREATE:
			{
				AddTrayIcon (hWnd);
				break;
			}
			case WM_CLOSE:
			{
				RemoveTrayIcon (hWnd);
				KillTimer (hWnd, FRAME_UPDATE_TIMER);
				KillTimer (hWnd, IDT_GRACEFUL_SHUTDOWN_TIMER);
				PostQuitMessage (0);
				break;
			}
			case WM_COMMAND:
			{
				switch (LOWORD(wParam))
				{
					case ID_ABOUT:
					{
						std::stringstream text;
						text << "Version: " << I2PD_VERSION << " " << CODENAME;
						MessageBox( hWnd, TEXT(text.str ().c_str ()), TEXT("i2pd"), MB_ICONINFORMATION | MB_OK );
						return 0;
					}
					case ID_EXIT:
					{
						PostMessage (hWnd, WM_CLOSE, 0, 0);
						return 0;
					}
					case ID_GRACEFUL_SHUTDOWN:
					{
						i2p::context.SetAcceptsTunnels (false);
						SetTimer (hWnd, IDT_GRACEFUL_SHUTDOWN_TIMER, 10*60*1000, nullptr); // 10 minutes
						i2p::util::DaemonWin32::Instance ().isGraceful = true;
						return 0;
					}
					case ID_STOP_GRACEFUL_SHUTDOWN:
					{
						i2p::context.SetAcceptsTunnels (true);
						KillTimer (hWnd, IDT_GRACEFUL_SHUTDOWN_TIMER);
						i2p::util::DaemonWin32::Instance ().isGraceful = false;
						return 0;
					}
					case ID_RELOAD:
					{
						i2p::client::context.ReloadConfig();
						std::stringstream text;
						text << "I2Pd reloading configs...";
						MessageBox( hWnd, TEXT(text.str ().c_str ()), TEXT("i2pd"), MB_ICONINFORMATION | MB_OK );
						return 0;
					}
					case ID_CONSOLE:
					{
						char buf[30];
						std::string httpAddr; i2p::config::GetOption("http.address", httpAddr);
						uint16_t	httpPort; i2p::config::GetOption("http.port", httpPort);
						snprintf(buf, 30, "http://%s:%d", httpAddr.c_str(), httpPort);
						ShellExecute(NULL, "open", buf, NULL, NULL, SW_SHOWNORMAL);
						return 0;
					}
					case ID_APP:
					{
						ShowWindow(hWnd, SW_SHOW);
						SetTimer(hWnd, FRAME_UPDATE_TIMER, 3000, NULL);
						return 0;
					}
				}
				break;
			}
			case WM_SYSCOMMAND:
			{
				switch (wParam)
				{
					case SC_MINIMIZE:
					{
						ShowWindow(hWnd, SW_HIDE);
						KillTimer (hWnd, FRAME_UPDATE_TIMER);
						return 0;
					}
					case SC_CLOSE:
					{
						std::string close; i2p::config::GetOption("close", close);
						if (0 == close.compare("ask"))
						switch(::MessageBox(hWnd, "Would you like to minimize instead of exiting?"
						" You can add 'close' configuration option. Valid values are: ask, minimize, exit.",
						"Minimize instead of exiting?", MB_ICONQUESTION | MB_YESNOCANCEL | MB_DEFBUTTON1))
						{
							case IDYES: close = "minimize"; break;
							case IDNO: close = "exit"; break;
							default: return 0;
						}
						if (0 == close.compare("minimize"))
						{
							ShowWindow(hWnd, SW_HIDE);
							KillTimer (hWnd, FRAME_UPDATE_TIMER);
							return 0;
						}
						if (0 != close.compare("exit"))
						{
							::MessageBox(hWnd, close.c_str(), "Unknown close action in config", MB_OK | MB_ICONWARNING);
							return 0;
						}
					}
				}
			}
			case WM_TRAYICON:
			{
				switch (lParam)
				{
					case WM_LBUTTONUP:
					case WM_RBUTTONUP:
					{
						SetForegroundWindow (hWnd);
						ShowPopupMenu(hWnd, NULL, -1);
						PostMessage (hWnd, WM_APP + 1, 0, 0);
						break;
					}
				}
				break;
			}
			case WM_TIMER:
			{
				if (wParam == IDT_GRACEFUL_SHUTDOWN_TIMER)
				{
					PostMessage (hWnd, WM_CLOSE, 0, 0); // exit
					return 0;
				}
				if (wParam == FRAME_UPDATE_TIMER)
				{
					InvalidateRect(hWnd, NULL, TRUE);
				}
				break;
			}
			case WM_PAINT:
			{
				HDC hDC;
				PAINTSTRUCT ps;
				RECT rp;
				HFONT hFont;
				std::stringstream s; PrintMainWindowText (s);
				hDC = BeginPaint (hWnd, &ps);
				GetClientRect(hWnd, &rp);
				SetTextColor(hDC, 0x00D43B69);
				hFont = CreateFont(18,0,0,0,0,0,0,0,DEFAULT_CHARSET,0,0,0,0,TEXT("Times New Roman"));
				SelectObject(hDC,hFont);
				DrawText(hDC, TEXT(s.str().c_str()), s.str().length(), &rp, DT_CENTER|DT_VCENTER);
				DeleteObject(hFont);
				EndPaint(hWnd, &ps);
				break;
			}
		}
		return DefWindowProc( hWnd, uMsg, wParam, lParam);
	}

	bool StartWin32App ()
	{
		if (FindWindow (I2PD_WIN32_CLASSNAME, TEXT("i2pd")))
		{
			MessageBox(NULL, TEXT("I2Pd is running already"), TEXT("Warning"), MB_OK);
			return false;
		}
		// register main window
		auto hInst = GetModuleHandle(NULL);
		WNDCLASSEX wclx;
		memset (&wclx, 0, sizeof(wclx));
		wclx.cbSize = sizeof(wclx);
		wclx.style = 0;
		wclx.lpfnWndProc = WndProc;
		//wclx.cbClsExtra = 0;
		//wclx.cbWndExtra = 0;
		wclx.hInstance = hInst;
		wclx.hIcon = LoadIcon (hInst, MAKEINTRESOURCE(MAINICON));
		wclx.hCursor = LoadCursor (NULL, IDC_ARROW);
		//wclx.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
		wclx.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
		wclx.lpszMenuName = NULL;
		wclx.lpszClassName = I2PD_WIN32_CLASSNAME;
		RegisterClassEx (&wclx);
		// create new window
		if (!CreateWindow(I2PD_WIN32_CLASSNAME, TEXT("i2pd"), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 100, 100, 350, 210, NULL, NULL, hInst, NULL))
		{
			MessageBox(NULL, "Failed to create main window", TEXT("Warning!"), MB_ICONERROR | MB_OK | MB_TOPMOST);
			return false;
		}
		return true;
	}

	int RunWin32App ()
	{
		MSG msg;
		while (GetMessage (&msg, NULL, 0, 0 ))
		{
			TranslateMessage (&msg);
			DispatchMessage (&msg);
		}
		return msg.wParam;
	}

	void StopWin32App ()
	{
		UnregisterClass (I2PD_WIN32_CLASSNAME, GetModuleHandle(NULL));
	}

	bool GracefulShutdown ()
	{
		HWND hWnd = FindWindow (I2PD_WIN32_CLASSNAME, TEXT("i2pd"));
		if (hWnd)
		PostMessage (hWnd, WM_COMMAND, MAKEWPARAM(ID_GRACEFUL_SHUTDOWN, 0), 0);
		return hWnd;
	}

	bool StopGracefulShutdown ()
	{
		HWND hWnd = FindWindow (I2PD_WIN32_CLASSNAME, TEXT("i2pd"));
		if (hWnd)
		PostMessage (hWnd, WM_COMMAND, MAKEWPARAM(ID_STOP_GRACEFUL_SHUTDOWN, 0), 0);
		return hWnd;
	}

}
}
