#include <string.h>
#include "Win32App.h"


static LRESULT CALLBACK WndProc (HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    }
    return DefWindowProc( hWnd, uMsg, wParam, lParam);
}

 int WINAPI WinMain (HINSTANCE hInst, HINSTANCE prev, LPSTR cmdline, int show)
 {
    // check if tunning already
    if (FindWindow (I2PD_WIN32_CLASSNAME, TEXT("Title")))
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
    //wclx.hIcon = LoadIcon( hInstance, MAKEINTRESOURCE( IDI_TRAYICON ) );
    //wclx.hIconSm = LoadSmallIcon( hInstance, IDI_TRAYICON );
    wclx.hCursor = LoadCursor (NULL, IDC_ARROW);
    wclx.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wclx.lpszMenuName = NULL;
    wclx.lpszClassName = I2PD_WIN32_CLASSNAME;
    RegisterClassEx (&wclx);
    // create new window
    if (!CreateWindow(I2PD_WIN32_CLASSNAME, TEXT("Title"), WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 250, 150, NULL, NULL, hInst, NULL))
    {
        MessageBox(NULL, "Failed to create main window", TEXT("Warning!"), MB_ICONERROR | MB_OK | MB_TOPMOST);
        return 1;
    }

    // start
    // main loop
    MSG msg;
    while (GetMessage (&msg, NULL, 0, 0 ))
    {
        TranslateMessage (&msg);
        DispatchMessage (&msg);
    }
    // atop
    // terminate
    UnregisterClass (I2PD_WIN32_CLASSNAME, hInst);
    return msg.wParam;
 }
