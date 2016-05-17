#include <string.h>
#include <windows.h>
#include <shellapi.h>
#include "../Config.h"
#include "../version.h"
#include "resource.h"
#include "Win32App.h"
#include <stdio.h>

#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf
#endif

#define ID_ABOUT 2000
#define ID_EXIT 2001
#define ID_CONSOLE 2002
#define ID_APP 2003

#define ID_TRAY_ICON 2050
#define WM_TRAYICON (WM_USER + 1)

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
        InsertMenu (hPopup, -1, MF_BYPOSITION | MF_SEPARATOR, NULL, NULL);
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
        strcpy (nid.szInfo, "i2pd is running");
        Shell_NotifyIcon(NIM_ADD, &nid );
    }

    static void RemoveTrayIcon (HWND hWnd)
    {
        NOTIFYICONDATA nid;
        nid.hWnd = hWnd;
        nid.uID = ID_TRAY_ICON;
        Shell_NotifyIcon (NIM_DELETE, &nid);
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
                    case ID_CONSOLE:
                    {
                        char buf[30];
                        std::string httpAddr; i2p::config::GetOption("http.address", httpAddr);
                        uint16_t    httpPort; i2p::config::GetOption("http.port", httpPort);
                        snprintf(buf, 30, "http://%s:%d", httpAddr.c_str(), httpPort);
                        ShellExecute(NULL, "open", buf, NULL, NULL, SW_SHOWNORMAL);
                        return 0;
                    }
                    case ID_APP:
                    {
                        ShowWindow(hWnd, SW_SHOW);
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
        wclx.cbClsExtra = 0;
        wclx.cbWndExtra = 0;
        wclx.hInstance = hInst;
        wclx.hIcon = LoadIcon (hInst, MAKEINTRESOURCE(MAINICON));
        wclx.hCursor = LoadCursor (NULL, IDC_ARROW);
        wclx.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wclx.lpszMenuName = NULL;
        wclx.lpszClassName = I2PD_WIN32_CLASSNAME;
        RegisterClassEx (&wclx);
        // create new window
        if (!CreateWindow(I2PD_WIN32_CLASSNAME, TEXT("i2pd"), WS_OVERLAPPEDWINDOW, 100, 100, 549, 738, NULL, NULL, hInst, NULL))
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
}
}
