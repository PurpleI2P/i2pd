#ifndef DAEMONQT_H
#define DAEMONQT_H

#include <QObject>
#include <QThread>

namespace i2p
{
namespace qt
{
    class Worker : public QObject
    {
        Q_OBJECT

    public slots:
        void startDaemon();
        void restartDaemon();
        void stopDaemon();

    signals:
        void resultReady();
    };

    class DaemonQTImpl
    {
    public:
        typedef void (*runningChangedCallback)();

        /**
         * @brief init
         * @param argc
         * @param argv
         * @return success
         */
        bool static init(int argc, char* argv[]);
        void static deinit();
        void static start();
        void static stop();
        void static restart();
        void static setRunningCallback(runningChangedCallback cb);
        bool static isRunning();
    private:
        void static setRunning(bool running);
    };

    class Controller : public QObject
    {
        Q_OBJECT
        QThread workerThread;
    public:
        Controller();
        ~Controller();
    public slots:
        void handleResults(){}
    signals:
        void startDaemon();
        void stopDaemon();
        void restartDaemon();
    };
}
}

#endif // DAEMONQT_H
