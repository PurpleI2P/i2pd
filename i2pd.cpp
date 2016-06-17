#ifndef ANDROID
# include <stdlib.h>
# include "Daemon.h"
#else
# include "qt/i2pd_qt/i2pd_qt_gui.h"
# include <QMessageBox>
# include <QApplication>
# include "DaemonQT.h"
# include "mainwindow.h"
# include <QThread>
#endif

int main( int argc, char* argv[] )
{
#ifdef ANDROID
    //int result = runGUI(argc, argv);
    //QMessageBox::information(0,"Debug","runGUI completed");
    QApplication app(argc, argv);
    qDebug("Initialising the daemon...");
    bool daemonInitSuccess = i2p::qt::DaemonQTImpl::init(argc, argv);
    if(!daemonInitSuccess) {
        QMessageBox::critical(0, "Error", "Daemon init failed");
        return 1;
    }
    qDebug("Initialised, creating the main window...");
    MainWindow w;
    qDebug("Before main window.show()...");
    w.show ();
    int result;
    {
        i2p::qt::Controller daemonQtController;
        qDebug("Starting the daemon...");
        emit daemonQtController.startDaemon();
        qDebug("Starting gui event loop...");
        result = app.exec();
        //QMessageBox::information(&w, "Debug", "exec finished");
    }
    i2p::qt::DaemonQTImpl::deinit();
    //QMessageBox::information(&w, "Debug", "demon stopped");
    //exit(result); //return from main() causes intermittent sigsegv bugs in some Androids. exit() is a workaround for this
    qDebug("Exiting the application");
    return result;
#else
    if (Daemon.init(argc, argv))
	{
		if (Daemon.start())
			Daemon.run ();
		Daemon.stop();
	}
	return EXIT_SUCCESS;
#endif
}

#ifdef _WIN32
#include <windows.h>

int CALLBACK WinMain(
	_In_ HINSTANCE hInstance,
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR     lpCmdLine,
	_In_ int       nCmdShow
	)
{
	return main(__argc, __argv);
}
#endif
