#include <memory>
#include "mainwindow.h"
#include <QApplication>
#include <stdlib.h>
#include "../../Daemon.h"

namespace i2p
{
namespace util
{
	std::unique_ptr<QApplication> app;
	bool DaemonQT::init(int argc, char* argv[])
	{
        app.reset (new QApplication (argc, argv));
        return Daemon_Singleton::init(argc, argv);
	}

	bool DaemonQT::start()
	{
		return Daemon_Singleton::start();
	}

	bool DaemonQT::stop()
	{
		return Daemon_Singleton::stop();
	}

	void DaemonQT::run ()
	{
		MainWindow w;
        w.show ();
        if (app)
        {
            app->exec();
            app.reset (nullptr);
        }
	}
}
}
