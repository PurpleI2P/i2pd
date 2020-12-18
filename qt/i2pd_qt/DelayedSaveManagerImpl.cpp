#include "DelayedSaveManagerImpl.h"

#include <assert.h>

DelayedSaveManagerImpl::DelayedSaveManagerImpl() :
    widgetToFocus(nullptr),
    saver(nullptr),
    lastDataSerialSeen(DelayedSaveManagerImpl::INITIAL_DATA_SERIAL),
    lastSaveStartedTimestamp(A_VERY_OBSOLETE_TIMESTAMP),
    exiting(false),
    thread(new DelayedSaveThread(this))
{
}

void DelayedSaveManagerImpl::setSaver(Saver* saver) {
    this->saver = saver;
}

void DelayedSaveManagerImpl::start() {
    thread->start();
}

bool DelayedSaveManagerImpl::isSaverValid() {
    return saver != nullptr;
}

void DelayedSaveManagerImpl::delayedSave(bool reloadAfterSave, DATA_SERIAL_TYPE dataSerial, FocusEnum focusOn, std::string tunnelNameToFocus, QWidget* widgetToFocus) {
    if(lastDataSerialSeen==dataSerial)return;
    this->reloadAfterSave = reloadAfterSave;
    this->focusOn = focusOn;
    this->tunnelNameToFocus = tunnelNameToFocus;
    this->widgetToFocus = widgetToFocus;
    lastDataSerialSeen=dataSerial;
    assert(isSaverValid());
    TIMESTAMP_TYPE now = getTime();
    TIMESTAMP_TYPE wakeTime = lastSaveStartedTimestamp + DelayedSaveThread::WAIT_TIME_MILLIS;
    if(now < wakeTime) {
        //defer save until lastSaveStartedTimestamp + DelayedSaveThread::WAIT_TIME_MILLIS
        thread->deferSaveUntil(wakeTime);
        return;
    }
    lastSaveStartedTimestamp = now;
    thread->startSavingNow();
}

bool DelayedSaveManagerImpl::appExiting() {
    exiting=true;
    thread->wakeThreadAndJoinThread();
    assert(isSaverValid());
    saver->save(false, FocusEnum::noFocus);
    return true;
}

DelayedSaveThread::DelayedSaveThread(DelayedSaveManagerImpl* delayedSaveManagerImpl_):
    delayedSaveManagerImpl(delayedSaveManagerImpl_),
    mutex(new QMutex()),
    waitCondition(new QWaitCondition()),
    saveNow(false),
    defer(false)
{
    mutex->lock();
}

DelayedSaveThread::~DelayedSaveThread(){
    mutex->unlock();
    delete mutex;
    delete waitCondition;
}

void DelayedSaveThread::run() {
    forever {
        if(delayedSaveManagerImpl->isExiting())return;
        waitCondition->wait(mutex, WAIT_TIME_MILLIS);
        if(delayedSaveManagerImpl->isExiting())return;
        Saver* saver = delayedSaveManagerImpl->getSaver();
        assert(saver!=nullptr);
        if(saveNow) {
            saveNow = false;
            const FocusEnum focusOn = delayedSaveManagerImpl->getFocusOn();
            const std::string tunnelNameToFocus = delayedSaveManagerImpl->getTunnelNameToFocus();
            QWidget* widgetToFocus = delayedSaveManagerImpl->getWidgetToFocus();
            saver->save(delayedSaveManagerImpl->isReloadAfterSave(), focusOn, tunnelNameToFocus, widgetToFocus);
            continue;
        }
        if(defer) {
            defer=false;
#define max(a,b) (((a)>(b))?(a):(b))
            forever {
                TIMESTAMP_TYPE now = DelayedSaveManagerImpl::getTime();
                TIMESTAMP_TYPE millisToWait = max(wakeTime-now, 0);
                if(millisToWait>0) {
                    waitCondition->wait(mutex, millisToWait);
                    if(delayedSaveManagerImpl->isExiting())return;
                    continue;
                }
                const FocusEnum focusOn = delayedSaveManagerImpl->getFocusOn();
                const std::string tunnelNameToFocus = delayedSaveManagerImpl->getTunnelNameToFocus();
                QWidget* widgetToFocus = delayedSaveManagerImpl->getWidgetToFocus();
                saver->save(delayedSaveManagerImpl->isReloadAfterSave(), focusOn, tunnelNameToFocus, widgetToFocus);
                break; //break inner loop
            }
        }
    }
}

void DelayedSaveThread::wakeThreadAndJoinThread() {
    waitCondition->wakeAll();
    quit();
    wait();//join //"similar to the POSIX pthread_join()"
}

DelayedSaveManagerImpl::TIMESTAMP_TYPE DelayedSaveManagerImpl::getTime() {
    return QDateTime::currentMSecsSinceEpoch();
}

void DelayedSaveThread::deferSaveUntil(TIMESTAMP_TYPE wakeTime_) {
    wakeTime = wakeTime_;
    defer = true;
    waitCondition->wakeAll();
}

void DelayedSaveThread::startSavingNow() {
    //mutex->lock();
    saveNow=true;
    waitCondition->wakeAll();
    //mutex->unlock();
}

DelayedSaveManagerImpl::~DelayedSaveManagerImpl() {
    thread->wakeThreadAndJoinThread();
    delete thread;
}

bool DelayedSaveManagerImpl::isExiting() {
    return exiting;
}
Saver* DelayedSaveManagerImpl::getSaver() {
    return saver;
}

