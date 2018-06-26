#ifndef LOGVIEWERMANAGER_H
#define LOGVIEWERMANAGER_H

#include <QObject>
#include <QString>
#include <QPlainTextEdit>
#include <QScrollBar>
#include <QComboBox>
#include <QTimer>
#include <QThread>

#include <assert.h>
#include <string>

#include "FS.h"
#include "Log.h"

class LogViewerManager;

namespace i2pd {
namespace qt {
namespace logviewer {

class Worker : public QObject
{
    Q_OBJECT
private:
    LogViewerManager &logViewerManager;
public:
    Worker(LogViewerManager &parameter1):logViewerManager(parameter1){}
private:
    QString pollAndShootATimerForInfiniteRetries();

public slots:
    void doWork1() {
        /* ... here is the expensive or blocking operation ... */
        QString read=pollAndShootATimerForInfiniteRetries();
        emit resultReady(read);
    }

signals:
    void resultReady(QString read);
};

class Controller : public QObject
{
    Q_OBJECT
    QThread workerThread;
    LogViewerManager& logViewerManager;
    int timerId;
public:
    Controller(LogViewerManager &parameter1);
    ~Controller() {
        if(timerId!=0)killTimer(timerId);
        workerThread.quit();
        workerThread.wait();
    }
signals:
    void operate1();
protected:
    void timerEvent(QTimerEvent */*event*/) {
        emit operate1();
    }
};

}
}
}

class LogViewerManager : public QObject
{
    Q_OBJECT
private:
    std::shared_ptr<std::iostream> logStream;
    QPlainTextEdit* logTextEdit;
    i2pd::qt::logviewer::Controller* controllerForBgThread;
public:
    //also starts a bg thread (QTimer) polling logStream->readsome(buf, n)
    explicit LogViewerManager(std::shared_ptr<std::iostream> logStream_,
                              QPlainTextEdit* logTextEdit_,
                              QObject *parent);
    //also deallocs the bg thread (QTimer)
    virtual ~LogViewerManager(){}
    const i2pd::qt::logviewer::Controller& getControllerForBgThread() {
        assert(controllerForBgThread!=nullptr);
        return *controllerForBgThread;
    }
    const QPlainTextEdit* getLogTextEdit(){ return logTextEdit; }
    const std::shared_ptr<std::iostream> getLogStream(){ return logStream; }
signals:

public slots:
    //void appendFromNonGuiThread(std::string read) {
    //}
public slots:
    void appendPlainText_atGuiThread(QString plainText) {
        if(plainText.length()==0)return;
        assert(logTextEdit!=nullptr);
        int scrollPosVert =logTextEdit->verticalScrollBar()->value();
        int scrollPosHoriz=logTextEdit->horizontalScrollBar()->value();
        int scrollPosVertMax =logTextEdit->verticalScrollBar()->maximum();
        const int MAX_LINES=10*1024;
        logTextEdit->setMaximumBlockCount(MAX_LINES);
        //logTextEdit->appendPlainText(plainText);
        //navigate the window to the end
        //QTextCursor cursor = logTextEdit->textCursor();
        //cursor.movePosition(QTextCursor::MoveOperation::End);
        //logTextEdit->setTextCursor(cursor);
        //QTextCursor prev_cursor = logTextEdit->textCursor();
        logTextEdit->moveCursor(QTextCursor::End);
        logTextEdit->insertPlainText(plainText);
        if(/*prev_cursor.atEnd()*/scrollPosVert==scrollPosVertMax){
            //logTextEdit->moveCursor(QTextCursor::End);
            scrollPosVert =logTextEdit->verticalScrollBar()->maximum();
            scrollPosHoriz=logTextEdit->horizontalScrollBar()->minimum();
        }
        //else
        //    logTextEdit->setTextCursor(prev_cursor);
        logTextEdit->verticalScrollBar()->setValue(scrollPosVert);
        logTextEdit->horizontalScrollBar()->setValue(scrollPosHoriz);
    }
    /*
    void replaceText_atGuiThread() {
        assert(logTextEdit!=nullptr);
        logTextEdit->setText(QString::fromStdString(nav.getContent()));
    }
    */
};

#endif // LOGVIEWERMANAGER_H
