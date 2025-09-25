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
#include "Transports.h"
#include "Daemon.h"

constexpr int M_GRACEFUL_SHUTDOWN = 1;
constexpr int C_GRACEFUL_SHUTDOWN_UPDATE = 2;
constexpr int C_MAIN_VIEW_UPDATE = 3;
constexpr int M_RUN_PEER_TEST = 4;
constexpr bigtime_t GRACEFUL_SHUTDOWN_UPDATE_INTERVAL = 1000*1100; // in microseconds, ~ 1 sec
constexpr int GRACEFUL_SHUTDOWN_UPDATE_COUNT = 600; // 10 minutes
constexpr bigtime_t MAIN_VIEW_UPDATE_INTERVAL = 5000*1000; // in miscroseconds, 5 secs

class MainWindow: public BWindow
{
	public:
		MainWindow ();
	
	private:
		void MessageReceived (BMessage * msg) override;	
	
		void UpdateMainView ();
	
	private:
		BMessenger m_Messenger;
		BStringView * m_MainView;
		std::unique_ptr<BMessageRunner> m_MainViewUpdateTimer, m_GracefulShutdownTimer;	
};	

class I2PApp: public BApplication
{
	public:
		I2PApp ();	
};

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
	auto commandsMenu = new BMenu ("Commands");
	commandsMenu->AddItem (new BMenuItem ("Run peer test", new BMessage (M_RUN_PEER_TEST), 'P'));
	menuBar->AddItem (commandsMenu);
	m_MainView = new BStringView (BRect (20, 21, 300, 250), nullptr, "Starting...", B_FOLLOW_ALL, B_WILL_DRAW);
	m_MainView->SetViewColor (255, 255, 255);
	m_MainView->SetHighColor (0xD4, 0x3B, 0x69);
	BFont font = *be_plain_font;
	font.SetSize (12);
	m_MainView->SetFont (&font);	
	AddChild (m_MainView);
	m_MainViewUpdateTimer = std::make_unique<BMessageRunner>(m_Messenger, 
		BMessage (C_MAIN_VIEW_UPDATE), MAIN_VIEW_UPDATE_INTERVAL);
}	

void MainWindow::UpdateMainView ()
{
	std::stringstream s;
	i2p::util::PrintMainWindowText (s);
	m_MainView->SetText (s.str ().c_str ());
}	

void MainWindow::MessageReceived (BMessage * msg)
{
	if (!msg) return;
	switch (msg->what)
	{
		case C_MAIN_VIEW_UPDATE:
			UpdateMainView ();
		break;
		case M_GRACEFUL_SHUTDOWN:
			if (!m_GracefulShutdownTimer)
			{
				i2p::context.SetAcceptsTunnels (false);
				Daemon.gracefulShutdownInterval = GRACEFUL_SHUTDOWN_UPDATE_COUNT;
				m_MainViewUpdateTimer = nullptr;
				m_GracefulShutdownTimer = std::make_unique<BMessageRunner>(m_Messenger, 
					BMessage (C_GRACEFUL_SHUTDOWN_UPDATE), GRACEFUL_SHUTDOWN_UPDATE_INTERVAL);
			}	
		break;
		case C_GRACEFUL_SHUTDOWN_UPDATE:
			if (Daemon.gracefulShutdownInterval > 0)
			{
				UpdateMainView ();
				Daemon.gracefulShutdownInterval--;
			}	
			if (!Daemon.gracefulShutdownInterval || i2p::tunnel::tunnels.CountTransitTunnels () <= 0)
			{
				m_GracefulShutdownTimer = nullptr;
				Daemon.gracefulShutdownInterval = 0;
				m_Messenger.SendMessage (B_QUIT_REQUESTED);
			}		
		break;
		case B_QUIT_REQUESTED:
			m_MainViewUpdateTimer = nullptr;
			m_GracefulShutdownTimer = nullptr;
			BWindow::MessageReceived (msg);
		break;
		case M_RUN_PEER_TEST:
			i2p::transport::transports.PeerTest ();
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



