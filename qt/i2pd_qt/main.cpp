#include "mainwindow.h"
#include <QApplication>
#include <stdlib.h>
#include "../../Daemon.h"

class DaemonQT: public i2p::util::Daemon_Singleton
{
	public:

		static DaemonQT& Instance()
		{
			static DaemonQT instance;
			return instance;
		}
};

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;

	int ret = -1;	
	if (DaemonQT::Instance ().init(argc, argv))
	{
		if (DaemonQT::Instance ().start())
		{
			w.show();	
			ret = a.exec();
		}
		DaemonQT::Instance ().stop();
	}

    return ret;
}
