#include "DaemonQT.h"
#include "../../Daemon.h"
#include <QMutex>
#include <QMutexLocker>

namespace i2p
{
namespace util
{
namespace DaemonQt
{

void Worker::startDaemon() {
    qDebug("Performing daemon start...");
    DaemonQTImpl::start();
    qDebug("Daemon started.");
    emit resultReady();
}
void Worker::restartDaemon() {
    qDebug("Performing daemon restart...");
    DaemonQTImpl::restart();
    qDebug("Daemon restarted.");
    emit resultReady();
}
void Worker::stopDaemon() {
    qDebug("Performing daemon stop...");
    DaemonQTImpl::stop();
    qDebug("Daemon stopped.");
    emit resultReady();
}

Controller::Controller() {
    Worker *worker = new Worker;
    worker->moveToThread(&workerThread);
    connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
    connect(this, &Controller::startDaemon, worker, &Worker::startDaemon);
    connect(this, &Controller::stopDaemon, worker, &Worker::stopDaemon);
    connect(this, &Controller::restartDaemon, worker, &Worker::restartDaemon);
    connect(worker, &Worker::resultReady, this, &Controller::handleResults);
    workerThread.start();
}
Controller::~Controller() {
    qDebug("Closing and waiting for daemon worker thread...");
    workerThread.quit();
    workerThread.wait();
    qDebug("Waiting for daemon worker thread finished.");
    if(i2p::util::DaemonQt::DaemonQTImpl::isRunning()) {
        qDebug("Stopping the daemon...");
        i2p::util::DaemonQt::DaemonQTImpl::stop();
        qDebug("Stopped the daemon.");
    }
}



static DaemonQTImpl::runningChangedCallback DaemonQTImpl_runningChanged;
static bool DaemonQTImpl_running;
static QMutex* mutex;

bool DaemonQTImpl::init(int argc, char* argv[]){mutex=new QMutex(QMutex::Recursive);setRunningCallback(0);DaemonQTImpl_running=false;return Daemon.init(argc,argv);}
void DaemonQTImpl::deinit(){delete mutex;}
void DaemonQTImpl::start(){QMutexLocker locker(mutex);setRunning(true);Daemon.start();}
void DaemonQTImpl::stop(){QMutexLocker locker(mutex);Daemon.stop();setRunning(false);}
void DaemonQTImpl::restart(){QMutexLocker locker(mutex);stop();start();}

void DaemonQTImpl::setRunningCallback(runningChangedCallback cb){DaemonQTImpl_runningChanged=cb;}
bool DaemonQTImpl::isRunning(){return DaemonQTImpl_running;}
void DaemonQTImpl::setRunning(bool newValue){
    bool oldValue = DaemonQTImpl_running;
    if(oldValue!=newValue) {
        DaemonQTImpl_running = newValue;
        if(DaemonQTImpl_runningChanged!=0)DaemonQTImpl_runningChanged();
    }
}

}
}
}

#if 0
#include <memory>
#include "mainwindow.h"
#include <QApplication>
#include <stdlib.h>
#include "../../Daemon.h"

namespace i2p
{
namespace util
{
	class DaemonQTImpl: public std::enable_shared_from_this<DaemonQTImpl>
	{
		public:

			DaemonQTImpl (int argc, char* argv[]):
				m_App (argc, argv)
			{
			}

			void Run ()
			{
                MainWindow w(m_App);
				w.show ();
                m_App.exec();
			}

		private:

			void StartDaemon ()
			{
				Daemon.start ();
			}

			void StopDaemon ()
			{
				Daemon.stop ();
			}	 

            bool IsRunning () const
			{
				return Daemon.running;
			}

		private:

			QApplication m_App;	
	};	

	bool DaemonQT::init(int argc, char* argv[])
	{
        m_Impl = std::make_shared<DaemonQTImpl> (argc, argv);
        return Daemon_Singleton::init(argc, argv);
	}

	void DaemonQT::run ()
	{
		if (m_Impl)
		{
			m_Impl->Run ();
			m_Impl = nullptr;
		}
	}
}
}
#endif
