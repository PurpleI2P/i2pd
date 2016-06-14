#include "mainwindow.h"
#include <QApplication>
#include <stdlib.h>
#include "../../Daemon.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;

    w.show();

	if (Daemon.init(argc, argv))
	{
		if (Daemon.start())
			Daemon.run ();
		Daemon.stop();
	}

    return a.exec();
}
