#include "pagewithbackbutton.h"
#include "QVBoxLayout"
#include "QHBoxLayout"
#include "QPushButton"

PageWithBackButton::PageWithBackButton(QWidget *parent, QWidget* child) : QWidget(parent)
{
    QVBoxLayout * layout = new QVBoxLayout();
    setLayout(layout);
    QWidget * topBar = new QWidget();
    QHBoxLayout * topBarLayout = new QHBoxLayout();
    topBar->setLayout(topBarLayout);
    layout->addWidget(topBar);
    layout->addWidget(child);

    QPushButton * backButton = new QPushButton(topBar);
    backButton->setText("< Back");
    topBarLayout->addWidget(backButton);
    connect(backButton, SIGNAL(released()), this, SLOT(backReleasedSlot()));
}

void PageWithBackButton::backReleasedSlot() {
    emit backReleased();
}
