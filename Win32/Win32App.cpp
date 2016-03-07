#include <string.h>
#include <windows.h>
#include <shellapi.h>
#include "Win32App.h"

#define ID_ABOUT 2000
#define ID_EXIT 2001

void ShowPopupMenu (HWND hWnd, POINT *curpos, int wDefaultItem)
{
    HMENU hPopup = CreatePopupMenu();
    InsertMenu (hPopup, 0, MF_BYPOSITION | MF_STRING, ID_ABOUT, "About...");
    InsertMenu (hPopup, 1, MF_BYPOSITION | MF_STRING, ID_EXIT , "Exit");
    SetMenuDefaultItem (hPopup, ID_ABOUT, FALSE);
    SetFocus (hWnd);
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

void AddTrayIcon (HWND hWnd, UINT uID, UINT uCallbackMsg, UINT uIcon)
{
    NOTIFYICONDATA nid;
    nid.hWnd = hWnd;
    nid.uID = uID;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = uCallbackMsg;
    nid.hIcon = LoadIcon (GetModuleHandle(NULL), IDI_APPLICATION);
    strcpy (nid.szTip, "i2pd");
    Shell_NotifyIcon(NIM_ADD, &nid );
}

void RemoveTrayIcon (HWND hWnd, UINT uID)
{
    NOTIFYICONDATA nid;
    nid.hWnd = hWnd;
    nid.uID = uID;
    Shell_NotifyIcon (NIM_DELETE, &nid);
}

static LRESULT CALLBACK WndProc (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
        {
            AddTrayIcon (hWnd, 1, WM_APP, 0);
            return 0;
        }
        case WM_CLOSE:
        {
            RemoveTrayIcon (hWnd, 1);
            PostQuitMessage (0);
            return DefWindowProc (hWnd, uMsg, wParam, lParam);
        }
        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
                case ID_ABOUT:
                {
                    MessageBox( hWnd, TEXT("i2pd"), TEXT("About"), MB_ICONINFORMATION | MB_OK );
                    return 0;
                }
                case ID_EXIT:
                {
                    PostMessage (hWnd, WM_CLOSE, 0, 0);
                    return 0;
                }
            }
            break;
        }
        case WM_APP:
        {
            switch (lParam)
            {
                case WM_RBUTTONUP:
                {
                    SetForegroundWindow (hWnd);
                    ShowPopupMenu(hWnd, NULL, -1);
                    PostMessage (hWnd, WM_APP + 1, 0, 0);
                    return 0;
                }
            }
            break;
        }
    }
    return DefWindowProc( hWnd, uMsg, wParam, lParam);
}

 int WINAPI WinMain (HINSTANCE hInst, HINSTANCE prev, LPSTR cmdline, int show)
 {
    // check if tunning already
    if (FindWindow (I2PD_WIN32_CLASSNAME, TEXT("i2pd")))
    {
        MessageBox(NULL, TEXT("I2Pd is running already"), TEXT("Warning"), MB_OK);
        return 0;
    }
    // register main window
    WNDCLASSEX wclx;
    memset (&wclx, 0, sizeof(wclx));
    wclx.cbSize = sizeof(wclx);
    wclx.style = 0;
    wclx.lpfnWndProc = &WndProc;
    wclx.cbClsExtra = 0;
    wclx.cbWndExtra = 0;
    wclx.hInstance = hInst;
    wclx.hIcon = LoadIcon (hInst, IDI_APPLICATION);
    wclx.hIconSm = LoadIcon (hInst, IDI_APPLICATION);
    wclx.hCursor = LoadCursor (NULL, IDC_ARROW);
    wclx.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wclx.lpszMenuName = NULL;
    wclx.lpszClassName = I2PD_WIN32_CLASSNAME;
    RegisterClassEx (&wclx);
    // create new window
    if (!CreateWindow(I2PD_WIN32_CLASSNAME, TEXT("i2pd"), WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 250, 150, NULL, NULL, hInst, NULL))
    {
        MessageBox(NULL, "Failed to create main window", TEXT("Warning!"), MB_ICONERROR | MB_OK | MB_TOPMOST);
        return 1;
    }

    // init
    int argc;
    auto argv = CommandLineToArgvW (cmdline, &argc)
    Daemon.init(argc, argv);
    LocalFree (argv);
    // start
    Daemon.start ();
    // main loop
    MSG msg;
    while (GetMessage (&msg, NULL, 0, 0 ))
    {
        TranslateMessage (&msg);
        DispatchMessage (&msg);
    }
    // atop
    Daemon.stop ();
    // terminate
    UnregisterClass (I2PD_WIN32_CLASSNAME, hInst);
    return msg.wParam;
 }
