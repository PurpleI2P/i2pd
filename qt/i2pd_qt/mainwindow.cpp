#include "mainwindow.h"
//#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QTimer>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)/*,
    ui(new Ui::MainWindow)*/
{
    //ui->setupUi(this);
    if (objectName().isEmpty())
        setObjectName(QStringLiteral("MainWindow"));
    resize(800, 480);
    centralWidget = new QWidget(this);
    centralWidget->setObjectName(QStringLiteral("centralWidget"));
    verticalLayoutWidget = new QWidget(centralWidget);
    verticalLayoutWidget->setObjectName(QStringLiteral("verticalLayoutWidget"));
    //verticalLayoutWidget->setGeometry(QRect(10, 20, 771, 441));
    verticalLayout1 = new QVBoxLayout(verticalLayoutWidget);
    verticalLayout1->setSpacing(6);
    verticalLayout1->setContentsMargins(11, 11, 11, 11);
    verticalLayout1->setObjectName(QStringLiteral("verticalLayout1"));
    verticalLayout1->setContentsMargins(0, 0, 0, 0);
    quitButton = new QPushButton(verticalLayoutWidget);
    quitButton->setObjectName(QStringLiteral("quitButton"));
    QSizePolicy sizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);
    sizePolicy.setHorizontalStretch(1);
    //sizePolicy.setVerticalStretch(1);
    sizePolicy.setHeightForWidth(quitButton->sizePolicy().hasHeightForWidth());
    quitButton->setSizePolicy(sizePolicy);
    verticalLayout1->addWidget(quitButton);
    gracefulQuitButton = new QPushButton(verticalLayoutWidget);
    gracefulQuitButton->setObjectName(QStringLiteral("gracefulQuitButton"));
    QSizePolicy sizePolicy2(QSizePolicy::Maximum, QSizePolicy::Maximum);
    sizePolicy2.setHorizontalStretch(1);
    //sizePolicy2.setVerticalStretch(1);
    sizePolicy2.setHeightForWidth(gracefulQuitButton->sizePolicy().hasHeightForWidth());
    gracefulQuitButton->setSizePolicy(sizePolicy2);
    verticalLayout1->addWidget(gracefulQuitButton);

    setCentralWidget(centralWidget);

    setWindowTitle(QApplication::translate("MainWindow", "MainWindow", 0));
    quitButton->setText(QApplication::translate("MainWindow", "Quit", 0));
    gracefulQuitButton->setText(QApplication::translate("MainWindow", "Graceful Quit", 0));

    QObject::connect(quitButton, SIGNAL(released()), this, SLOT(handleQuitButton()));
    QObject::connect(gracefulQuitButton, SIGNAL(released()), this, SLOT(handleGracefulQuitButton()));

    //QMetaObject::connectSlotsByName(this);
}

void MainWindow::handleQuitButton() {
    qDebug("Quit pressed. Hiding the main window");
    close();
    QApplication::instance()->quit();
}

void MainWindow::handleGracefulQuitButton() {
    qDebug("Graceful Quit pressed.");
    gracefulQuitButton->setText(QApplication::translate("MainWindow", "Graceful quit is in progress", 0));
    gracefulQuitButton->setEnabled(false);
    gracefulQuitButton->adjustSize();
    verticalLayoutWidget->adjustSize();
    //here, the code to stop tunnels
    QTimer::singleShot(10*60*1000/*millis*/, this, SLOT(handleGracefulQuitTimerEvent()));
}

void MainWindow::handleGracefulQuitTimerEvent() {
    qDebug("Hiding the main window");
    close();
    qDebug("Performing quit");
    QApplication::instance()->quit();
}

MainWindow::~MainWindow()
{
    qDebug("Destroying main window");
    //QMessageBox::information(0, "Debug", "mw destructor 1");
    //delete ui;
    //QMessageBox::information(0, "Debug", "mw destructor 2");
}
