/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <iostream>
#include <chrono>
#include <thread>
#include <exception>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/exception_ptr.hpp>
//#include "mainwindow.h"
#include "FS.h"
#include "DaemonAndroid.h"
#include "Daemon.h"

namespace i2p
{
namespace android
{
/*	Worker::Worker (DaemonAndroidImpl& daemon):
		m_Daemon (daemon)
	{
	}

	void Worker::startDaemon()
	{
		Log.d(TAG"Performing daemon start...");
		m_Daemon.start();
		Log.d(TAG"Daemon started.");
		emit resultReady();
	}
	void Worker::restartDaemon()
	{
		Log.d(TAG"Performing daemon restart...");
		m_Daemon.restart();
		Log.d(TAG"Daemon restarted.");
		emit resultReady();
	}
	void Worker::stopDaemon() {
		Log.d(TAG"Performing daemon stop...");
		m_Daemon.stop();
		Log.d(TAG"Daemon stopped.");
		emit resultReady();
	}

	Controller::Controller(DaemonAndroidImpl& daemon):
		m_Daemon (daemon)
	{
		Worker *worker = new Worker (m_Daemon);
		worker->moveToThread(&workerThread);
		connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
		connect(this, &Controller::startDaemon, worker, &Worker::startDaemon);
		connect(this, &Controller::stopDaemon, worker, &Worker::stopDaemon);
		connect(this, &Controller::restartDaemon, worker, &Worker::restartDaemon);
		connect(worker, &Worker::resultReady, this, &Controller::handleResults);
		workerThread.start();
	}
	Controller::~Controller()
	{
		Log.d(TAG"Closing and waiting for daemon worker thread...");
		workerThread.quit();
		workerThread.wait();
		Log.d(TAG"Waiting for daemon worker thread finished.");
		if(m_Daemon.isRunning())
		{
			Log.d(TAG"Stopping the daemon...");
			m_Daemon.stop();
			Log.d(TAG"Stopped the daemon.");
		}
	}
*/
	std::string dataDir = "";

	DaemonAndroidImpl::DaemonAndroidImpl ()
		//:
		/*mutex(nullptr), */
		//m_IsRunning(false),
		//m_RunningChangedCallback(nullptr)
	{
	}

	DaemonAndroidImpl::~DaemonAndroidImpl ()
	{
		//delete mutex;
	}

	bool DaemonAndroidImpl::init(int argc, char* argv[])
	{
		//mutex=new QMutex(QMutex::Recursive);
		//setRunningCallback(0);
		//m_IsRunning=false;

		// make sure assets are ready before proceed
		i2p::fs::DetectDataDir(dataDir, false);
		int numAttempts = 0;
		do
		{
			if (i2p::fs::Exists (i2p::fs::DataDirPath("assets.ready"))) break; // assets ready
			numAttempts++;
			std::this_thread::sleep_for (std::chrono::seconds(1)); // otherwise wait for 1 more second
		}
		while (numAttempts <= 10); // 10 seconds max
		return Daemon.init(argc,argv);
	}

	void DaemonAndroidImpl::start()
	{
		//QMutexLocker locker(mutex);
		//setRunning(true);
		Daemon.start();
	}

	void DaemonAndroidImpl::stop()
	{
		//QMutexLocker locker(mutex);
		Daemon.stop();
		//setRunning(false);
	}

	void DaemonAndroidImpl::restart()
	{
		//QMutexLocker locker(mutex);
		stop();
		start();
	}
	/*
	void DaemonAndroidImpl::setRunningCallback(runningChangedCallback cb)
	{
		m_RunningChangedCallback = cb;
	}

	bool DaemonAndroidImpl::isRunning()
	{
		return m_IsRunning;
	}

	void DaemonAndroidImpl::setRunning(bool newValue)
	{
		bool oldValue = m_IsRunning;
		if(oldValue!=newValue)
		{
			m_IsRunning = newValue;
			if(m_RunningChangedCallback)
				m_RunningChangedCallback();
		}
	}
*/
	static DaemonAndroidImpl daemon;
	static char* argv[1]={strdup("tmp")};
	/**
	 * returns error details if failed
	 * returns "ok" if daemon initialized and started okay
	 */
	std::string start(/*int argc, char* argv[]*/)
	{
		try
		{
			//int result;

			{
				//Log.d(TAG"Initialising the daemon...");
				bool daemonInitSuccess = daemon.init(1,argv);
				if(!daemonInitSuccess)
				{
					//QMessageBox::critical(0, "Error", "Daemon init failed");
					return "Daemon init failed";
				}
				//Log.d(TAG"Initialised, creating the main window...");
				//MainWindow w;
				//Log.d(TAG"Before main window.show()...");
				//w.show ();

				{
					//i2p::qt::Controller daemonQtController(daemon);
					//Log.d(TAG"Starting the daemon...");
					//emit daemonQtController.startDaemon();
					//daemon.start ();
					//Log.d(TAG"Starting GUI event loop...");
					//result = app.exec();
					//daemon.stop ();
					daemon.start();
				}
			}

			//QMessageBox::information(&w, "Debug", "demon stopped");
			//Log.d(TAG"Exiting the application");
			//return result;
		}
		catch (boost::exception& ex)
		{
			std::stringstream ss;
			ss << boost::diagnostic_information(ex);
			return ss.str();
		}
		catch (std::exception& ex)
		{
			std::stringstream ss;
			ss << ex.what();
			return ss.str();
		}
		catch(...)
		{
			return "unknown exception";
		}
		return "ok";
	}

	void stop()
	{
		daemon.stop();
	}

	void SetDataDir(std::string jdataDir)
	{
		dataDir = jdataDir;
	}
}
}
