#ifndef WIDGETLOCKREGISTRY_H
#define WIDGETLOCKREGISTRY_H

#include <vector>
#include <widgetlock.h>

class widgetlockregistry {
    std::vector<widgetlock*> locks;

public:
    widgetlockregistry() : locks() {}
    virtual ~widgetlockregistry() {
        while(!locks.empty()) {
            delete locks.back();
            locks.pop_back();
        }
    }
    void add(widgetlock* lock) {
        locks.push_back(lock);
    }
};

#endif // WIDGETLOCKREGISTRY_H
