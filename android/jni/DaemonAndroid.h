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
