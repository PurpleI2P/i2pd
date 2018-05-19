#include "logviewermanager.h"

LogViewerManager::LogViewerManager(std::shared_ptr<std::iostream> logStream_,
                                   QPlainTextEdit* logTextEdit_,
                                   QObject *parent) :
    QObject(parent),
    logStream(logStream_),
    logTextEdit(logTextEdit_),
    controllerForBgThread(nullptr)
{
    assert(logTextEdit!=nullptr);
    controllerForBgThread=new i2pd::qt::logviewer::Controller(*this);
}

namespace i2pd {
namespace qt {
namespace logviewer {

QString Worker::pollAndShootATimerForInfiniteRetries() {
    std::shared_ptr<std::iostream> logStream=logViewerManager.getLogStream();
    assert(logStream!=nullptr);
    std::streamsize MAX_SZ=64*1024;
    char*buf=(char*)malloc(MAX_SZ*sizeof(char));
    if(buf==nullptr)return "";
    std::streamsize read=logStream->readsome(buf, MAX_SZ);
    if(read<0)read=0;
    QString ret=QString::fromUtf8(buf, read);
    free(buf);
    return ret;
}

Controller::Controller(LogViewerManager &parameter1):logViewerManager(parameter1) {
    Worker *worker = new Worker(parameter1);
    worker->moveToThread(&workerThread);
    connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
    connect(this, &Controller::operate1, worker, &Worker::doWork1);
    connect(worker, &Worker::resultReady,
            &parameter1, &LogViewerManager::appendPlainText_atGuiThread);
    workerThread.start();
    timerId=startTimer(100/*millis*/);
}

}
}
}
