#ifndef SAVER_H
#define SAVER_H

#include <string>
#include <QObject>
#include <QString>

class Saver : public QObject
{
    Q_OBJECT

public:
    Saver();
    //false iff failures
    virtual bool save(const bool focusOnTunnel, const std::string& tunnelNameToFocus)=0;

signals:
    void reloadTunnelsConfigAndUISignal(const QString);

};

#endif // SAVER_H
