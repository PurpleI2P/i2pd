/*
* Copyright (c) 2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#if defined(__HAIKU__)

#include <memory>
#include <string>
#include <MenuItem.h>
#include <MenuBar.h>
#include <StringView.h>
#include <Font.h>
#include <MessageRunner.h>
#include <Window.h>
#include <Application.h>
#include <Alert.h>

#include "version.h"
#include "Log.h"
#include "Config.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "Daemon.h"

constexpr int M_GRACEFUL_SHUTDOWN = 1;
constexpr int C_GRACEFUL_SHUTDOWN_UPDATE = 2;
constexpr bigtime_t GRACEFUL_SHUTDOWN_UPDATE_INTERVAL = 1000*1000; // in microseconds
constexpr int GRACEFUL_SHUTDOWN_UPDATE_COUNT = 600; // 10 minutes

class MainWindowView: public BStringView
{
	public:
		MainWindowView (BRect r);
	
	private:
		void Draw (BRect updateRect) override;
		
};	

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

MainWindowView::MainWindowView (BRect r):
	BStringView (r, nullptr, nullptr, B_FOLLOW_ALL, B_WILL_DRAW)
{
	SetViewColor (255, 255, 255);
	SetHighColor (0xD4, 0x3B, 0x69);
	BFont font = *be_plain_font;
	font.SetSize (12);
	SetFont (&font);
}	

void MainWindowView::Draw (BRect updateRect)
{
	std::stringstream s;
	i2p::util::PrintMainWindowText (s);
	SetText (s.str ().c_str ());
	BStringView::Draw (updateRect);
}	

MainWindow::MainWindow ():
	BWindow (BRect(100, 100, 500, 400), "i2pd " VERSION, B_TITLED_WINDOW, B_QUIT_ON_WINDOW_CLOSE),
	m_Messenger (nullptr, this)
{	
	auto r = Bounds (); r.bottom = 20;
	auto menuBar = new BMenuBar (r, "menubar");
	AddChild (menuBar);
	auto runMenu = new BMenu ("Run");
	runMenu->AddItem (new BMenuItem ("Graceful shutdown", new BMessage (M_GRACEFUL_SHUTDOWN), 'G'));
	runMenu->AddItem (new BMenuItem ("Quit", new BMessage (B_QUIT_REQUESTED), 'Q'));
	menuBar->AddItem (runMenu);
	r = Bounds (); r.left = 20; r.top = 21;
	auto view = new MainWindowView (r);	
	AddChild (view);
}	

void MainWindow::MessageReceived (BMessage * msg)
{
	if (!msg) return;
	switch (msg->what)
	{
		case M_GRACEFUL_SHUTDOWN:
			if (!m_GracefulShutdownTimer)
			{
				i2p::context.SetAcceptsTunnels (false);
				Daemon.gracefulShutdownInterval = GRACEFUL_SHUTDOWN_UPDATE_COUNT;
				m_GracefulShutdownTimer = std::make_unique<BMessageRunner>(m_Messenger, 
					BMessage (C_GRACEFUL_SHUTDOWN_UPDATE), GRACEFUL_SHUTDOWN_UPDATE_INTERVAL);
			}	
		break;
		case C_GRACEFUL_SHUTDOWN_UPDATE:
			if (Daemon.gracefulShutdownInterval > 0) Daemon.gracefulShutdownInterval--;
			if (!Daemon.gracefulShutdownInterval || i2p::tunnel::tunnels.CountTransitTunnels () <= 0)
			{
				m_GracefulShutdownTimer = nullptr;
				Daemon.gracefulShutdownInterval = 0;
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
	bool DaemonHaiku::init(int argc, char* argv[])
	{
		i2p::config::GetOption("daemon", isDaemon);
		if (!isDaemon)
		{
			new I2PApp(); // set be_app
			i2p::log::SetThrowFunction ([](const std::string& s)
				{
					auto alert = new BAlert (nullptr, s.c_str (), "Quit", nullptr, nullptr,
						B_WIDTH_AS_USUAL, B_OFFSET_SPACING, B_STOP_ALERT);
					alert->Go ();
				});
		}	
		return Daemon_Singleton::init (argc, argv);
	}	
	
	void DaemonHaiku::run ()
	{
		if (be_app)
		{
			be_app->Run ();
			delete be_app;
		}		
		else
			DaemonUnix::run ();
	}	
}	
}	

#endif



