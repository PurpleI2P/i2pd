#ifndef PAGEWITHBACKBUTTON_H
#define PAGEWITHBACKBUTTON_H

#include <QWidget>

class PageWithBackButton : public QWidget
{
    Q_OBJECT
public:
    explicit PageWithBackButton(QWidget *parent, QWidget* child);

signals:

    void backReleased();

private slots:

    void backReleasedSlot();
};

#endif // PAGEWITHBACKBUTTON_H
