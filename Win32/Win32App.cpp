#include <string.h>
#include <windows.h>
#include <shellapi.h>
//#include "../Daemon.h"
#include "resource.h"
#include "Win32App.h"

#define ID_ABOUT 2000
#define ID_EXIT 2001

#define ID_TRAY_ICON 2050
#define WM_TRAYICON (WM_USER + 1)

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

void AddTrayIcon (HWND hWnd)
{
    NOTIFYICONDATA nid;
    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = hWnd;
    nid.uID = ID_TRAY_ICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    // TODO: must set correct icon
   // nid.hIcon = LoadIcon (GetModuleHandle(NULL), MAKEINTRESOURCE (IDI_ICON1));
    {
        char    szIconFile[512];

        GetSystemDirectory( szIconFile, sizeof( szIconFile ) );
        if ( szIconFile[ strlen( szIconFile ) - 1 ] != '\\' )
            strcat( szIconFile, "\\" );
        strcat( szIconFile, "shell32.dll" );
        //  Icon #23 (0-indexed) in shell32.dll is a "help" icon.
        ExtractIconEx( szIconFile, 23, NULL, &(nid.hIcon), 1 );
    }
    strcpy (nid.szTip, "i2pd");
    Shell_NotifyIcon(NIM_ADD, &nid );
}

void RemoveTrayIcon (HWND hWnd)
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
        case WM_TRAYICON:
        {
            SetForegroundWindow (hWnd);
            switch (lParam)
            {
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
    wclx.lpfnWndProc = WndProc;
    wclx.cbClsExtra = 0;
    wclx.cbWndExtra = 0;
    wclx.hInstance = hInst;
    wclx.hIcon = LoadIcon (hInst, MAKEINTRESOURCE (IDI_ICON1));
    wclx.hIconSm = LoadIcon (hInst, MAKEINTRESOURCE (IDI_ICON1));
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

  /*  // init
    char * argv[] = { (char *)"i2pd" };
    Daemon.init(sizeof (argv)/sizeof (argv[0]), argv);
    // start
    Daemon.start ();*/
    // main loop
    MSG msg;
    while (GetMessage (&msg, NULL, 0, 0 ))
    {
        TranslateMessage (&msg);
        DispatchMessage (&msg);
    }
   /* // atop
    Daemon.stop ();*/
    // terminate
    UnregisterClass (I2PD_WIN32_CLASSNAME, hInst);
    return msg.wParam;
 }
