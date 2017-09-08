#ifndef WIDGETLOCK_H
#define WIDGETLOCK_H

#include <QWidget>
#include <QObject>
#include <QPushButton>
#include <QApplication>

class widgetlock : public QObject {
    Q_OBJECT

private:
    QWidget* widget;
    QPushButton* lockButton;

public slots:
    void lockButtonClicked(bool) {
        bool wasEnabled = widget->isEnabled();
        widget->setEnabled(!wasEnabled);
        lockButton->setText(widget->isEnabled()?lockButton->tr("Lock"):lockButton->tr("Edit"));
    }

public:
    widgetlock(QWidget* widget_, QPushButton* lockButton_): widget(widget_),lockButton(lockButton_) {
        widget->setEnabled(false);
        lockButton->setText(lockButton->tr("Edit"));
        QObject::connect(lockButton,SIGNAL(clicked(bool)), this, SLOT(lockButtonClicked(bool)));
    }
    virtual ~widgetlock() {}
    void deleteListener() {
        QObject::disconnect(lockButton,SIGNAL(clicked(bool)), this, SLOT(lockButtonClicked(bool)));
    }
};

#endif // WIDGETLOCK_H
