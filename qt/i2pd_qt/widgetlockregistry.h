#ifndef WIDGETLOCKREGISTRY_H
#define WIDGETLOCKREGISTRY_H

#include <vector>
#include <widgetlock.h>

class widgetlockregistry {
    std::vector<widgetlock*> locks;

public:
    widgetlockregistry() : locks() {}
    virtual ~widgetlockregistry() {}
    void add(widgetlock* lock) {
        locks.push_back(lock);
    }

    void deleteListeners() {
        while(!locks.empty()) {
            widgetlock* lock = locks.back();
            lock->deleteListener();
            delete lock;
            locks.pop_back();
        }
    }
};

#endif // WIDGETLOCKREGISTRY_H
