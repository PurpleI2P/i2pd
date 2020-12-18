#ifndef DELAYEDSAVEMANAGERIMPL_H
#define DELAYEDSAVEMANAGERIMPL_H

#include <QObject>
#include <QThread>
#include <QWaitCondition>
#include <QMutex>
#include <QDateTime>

#include "I2pdQtTypes.h"
#include "DelayedSaveManager.h"
#include "Saver.h"

class DelayedSaveManagerImpl;
class Saver;

class DelayedSaveThread : public QThread {
    Q_OBJECT

public:
    static constexpr unsigned long WAIT_TIME_MILLIS = 1000L;

    typedef qint64 TIMESTAMP_TYPE;
    static constexpr TIMESTAMP_TYPE A_VERY_OBSOLETE_TIMESTAMP=0;

    DelayedSaveThread(DelayedSaveManagerImpl* delayedSaveManagerImpl);
    virtual ~DelayedSaveThread();

    void run() override;

    void deferSaveUntil(TIMESTAMP_TYPE wakeTime);
    void startSavingNow();

    void wakeThreadAndJoinThread();

private:
    DelayedSaveManagerImpl* delayedSaveManagerImpl;
    QMutex* mutex;
    QWaitCondition* waitCondition;
    volatile bool saveNow;
    volatile bool defer;
    volatile TIMESTAMP_TYPE wakeTime;
};

class DelayedSaveManagerImpl : public DelayedSaveManager {
    FocusEnum focusOn;
    std::string tunnelNameToFocus;
    QWidget* widgetToFocus;
    bool reloadAfterSave;
public:
    DelayedSaveManagerImpl();
    virtual ~DelayedSaveManagerImpl();
    virtual void setSaver(Saver* saver);
    virtual void start();
    virtual void delayedSave(bool reloadAfterSave, DATA_SERIAL_TYPE dataSerial, FocusEnum focusOn, std::string tunnelNameToFocus, QWidget* widgetToFocus);
    virtual bool appExiting();

    typedef DelayedSaveThread::TIMESTAMP_TYPE TIMESTAMP_TYPE;

    static constexpr DATA_SERIAL_TYPE INITIAL_DATA_SERIAL=0;
    bool isExiting();
    Saver* getSaver();
    static TIMESTAMP_TYPE getTime();

    bool isReloadAfterSave() { return reloadAfterSave; }
    FocusEnum getFocusOn() { return focusOn; }
    std::string& getTunnelNameToFocus() { return tunnelNameToFocus; }
    QWidget* getWidgetToFocus() { return widgetToFocus; }

private:
    Saver* saver;
    bool isSaverValid();

    DATA_SERIAL_TYPE lastDataSerialSeen;

    static constexpr TIMESTAMP_TYPE A_VERY_OBSOLETE_TIMESTAMP=DelayedSaveThread::A_VERY_OBSOLETE_TIMESTAMP;
    TIMESTAMP_TYPE lastSaveStartedTimestamp;

    bool exiting;
    DelayedSaveThread* thread;
    void wakeThreadAndJoinThread();
};

#endif // DELAYEDSAVEMANAGERIMPL_H
