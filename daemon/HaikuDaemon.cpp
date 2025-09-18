/*
* Copyright (c) 2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#if defined(__HAIKU__)

#include "Daemon.h"

#include <MenuItem.h>
#include <MenuBar.h>
#include <Window.h>
#include <Application.h>

class MainWindow: public BWindow
{
	public:
		MainWindow ();
};	

class I2PApp: public BApplication
{
	public:
		I2PApp ();
};

MainWindow::MainWindow ():
	BWindow (BRect(100, 100, 500, 400), "i2pd", B_TITLED_WINDOW, B_QUIT_ON_WINDOW_CLOSE)
{	
	auto r = Bounds (); r.bottom = 20;
	auto menuBar = new BMenuBar (r, "menubar");
	AddChild (menuBar);
	auto runMenu = new BMenu ("Run");
	runMenu->AddItem (new BMenuItem ("Quit", new BMessage (B_QUIT_REQUESTED), 'Q'));
	menuBar->AddItem (runMenu);
}	

I2PApp::I2PApp (): BApplication("application/x-vnd.purplei2p-i2pd")
{
	auto mainWindow = new MainWindow ();
	mainWindow->Show ();
}	

namespace i2p
{
namespace util
{
	void DaemonHaiku::run ()
	{
		if (isDaemon)
			DaemonUnix::run ();
		else
		{
			I2PApp app;
			app.Run ();
		}		
	}	
}	
}	

#endif



