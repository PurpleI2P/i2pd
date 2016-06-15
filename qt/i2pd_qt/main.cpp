#include "mainwindow.h"
#include <QApplication>
#include <stdlib.h>
#include "../../Daemon.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;

	int ret = -1;	
	if (Daemon.init(argc, argv))
	{
		if (Daemon.start())
		{
			w.show();	
			ret = a.exec();
		}
		Daemon.stop();
	}

    return ret;
}
