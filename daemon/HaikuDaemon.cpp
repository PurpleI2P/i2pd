/*
* Copyright (c) 2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#if defined(__HAIKU__)

#include <memory>
#include <MenuItem.h>
#include <MenuBar.h>
#include <MessageRunner.h>
#include <Window.h>
#include <Application.h>

#include "RouterContext.h"
#include "Tunnel.h"
#include "Daemon.h"

constexpr int M_GRACEFUL_SHUTDOWN = 1;
constexpr int C_GRACEFUL_SHUTDOWN_UPDATE = 2;
constexpr bigtime_t GRACEFUL_SHUTDOWN_UPDATE_INTERVAL = 1000*1000; // in microseconds
constexpr int GRACEFUL_SHUTDOWN_UPDATE_COUNT = 600; // 10 minutes

class MainWindow: public BWindow
{
	public:
		MainWindow ();
	
	private:
		void MessageReceived (BMessage * msg) override;	
	
	private:
		BMessenger m_Messenger;
		std::unique_ptr<BMessageRunner> m_GracefulShutdownTimer;	
};	

class I2PApp: public BApplication
{
	public:
		I2PApp ();	
};

MainWindow::MainWindow ():
	BWindow (BRect(100, 100, 500, 400), "i2pd", B_TITLED_WINDOW, B_QUIT_ON_WINDOW_CLOSE),
	m_Messenger (nullptr, this)
{	
	auto r = Bounds (); r.bottom = 20;
	auto menuBar = new BMenuBar (r, "menubar");
	AddChild (menuBar);
	auto runMenu = new BMenu ("Run");
	runMenu->AddItem (new BMenuItem ("Graceful shutdown", new BMessage (M_GRACEFUL_SHUTDOWN), 'G'));
	runMenu->AddItem (new BMenuItem ("Quit", new BMessage (B_QUIT_REQUESTED), 'Q'));
	menuBar->AddItem (runMenu);
}	

void MainWindow::MessageReceived (BMessage * msg)
{
	if (!msg) return;
	switch (msg->what)
	{
		case M_GRACEFUL_SHUTDOWN:
			i2p::context.SetAcceptsTunnels (false);
			m_GracefulShutdownTimer = std::make_unique<BMessageRunner>(m_Messenger, 
				BMessage (C_GRACEFUL_SHUTDOWN_UPDATE), GRACEFUL_SHUTDOWN_UPDATE_INTERVAL);
		break;
		case C_GRACEFUL_SHUTDOWN_UPDATE:
			if (i2p::tunnel::tunnels.CountTransitTunnels () <= 0)
			{
				m_GracefulShutdownTimer = nullptr;
				m_Messenger.SendMessage (B_QUIT_REQUESTED);
			}	
		break;
		default:
			BWindow::MessageReceived (msg);
	}	
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



