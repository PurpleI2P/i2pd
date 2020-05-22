/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef DAEMON_ANDROID_H
#define DAEMON_ANDROID_H

#include <string>

namespace i2p
{
namespace android
{
	class DaemonAndroidImpl
	{
	public:

		DaemonAndroidImpl ();
		~DaemonAndroidImpl ();

		//typedef void (*runningChangedCallback)();

		/**
		 * @return success
		 */
		bool init(int argc, char* argv[]);
		void start();
		void stop();
		void restart();
		//void setRunningCallback(runningChangedCallback cb);
		//bool isRunning();
	private:
		//void setRunning(bool running);
	private:
		//QMutex* mutex;
		//bool m_IsRunning;
		//runningChangedCallback m_RunningChangedCallback;
	};

	/**
	 * returns "ok" if daemon init failed
	 * returns errinfo if daemon initialized and started okay
	 */
	std::string start();

	// stops the daemon
	void stop();

	// set datadir received from jni
	void SetDataDir(std::string jdataDir);
	/*
	class Worker : public QObject
	{
		Q_OBJECT
	public:

		Worker (DaemonAndroidImpl& daemon);

	private:

		DaemonAndroidImpl& m_Daemon;

	public slots:
		void startDaemon();
		void restartDaemon();
		void stopDaemon();

	signals:
		void resultReady();
	};

	class Controller : public QObject
	{
		Q_OBJECT
		QThread workerThread;
	public:
		Controller(DaemonAndroidImpl& daemon);
		~Controller();
	private:
		DaemonAndroidImpl& m_Daemon;

	public slots:
		void handleResults(){}
	signals:
		void startDaemon();
		void stopDaemon();
		void restartDaemon();
	};
	*/
}
}

#endif // DAEMON_ANDROID_H
