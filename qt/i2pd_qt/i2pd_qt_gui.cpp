#if 0
#include "i2pd_qt_gui.h"
#include <QApplication>
#include <QMessageBox>
#include "mainwindow.h"
#include "DaemonQT.h"

int runGUI( int argc, char* argv[] ) {
    QApplication app(argc, argv);
    bool daemonInitSuccess = i2p::util::DaemonQTImpl::init(argc, argv);
    if(!daemonInitSuccess) {
        QMessageBox::critical(0, "Error", "Daemon init failed");
        return 1;
    }
    MainWindow w;
    w.show ();
    i2p::util::DaemonQTImpl::start();
    int result = app.exec();
    //QMessageBox::information(&w, "Debug", "exec finished");
    i2p::util::DaemonQTImpl::stop();
    //QMessageBox::information(&w, "Debug", "demon stopped");
    return result;
}
#endif
