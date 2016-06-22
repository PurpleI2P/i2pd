#include "mainwindow.h"
//#include "ui_mainwindow.h"
#include <QMessageBox>

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
    QSizePolicy sizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed);
    sizePolicy.setHorizontalStretch(0);
    sizePolicy.setVerticalStretch(0);
    sizePolicy.setHeightForWidth(quitButton->sizePolicy().hasHeightForWidth());
    quitButton->setSizePolicy(sizePolicy);

    verticalLayout1->addWidget(quitButton);

    setCentralWidget(centralWidget);

    setWindowTitle(QApplication::translate("MainWindow", "MainWindow", 0));
    quitButton->setText(QApplication::translate("MainWindow", "Quit", 0));

    QObject::connect(quitButton, SIGNAL(released()), this, SLOT(handleQuitButton()));

    //QMetaObject::connectSlotsByName(this);
}

void MainWindow::handleQuitButton() {
    qDebug("Quit pressed. Hiding the main window");
    close();
    QApplication::instance()->quit();
}

MainWindow::~MainWindow()
{
    qDebug("Destroying main window");
    //QMessageBox::information(0, "Debug", "mw destructor 1");
    //delete ui;
    //QMessageBox::information(0, "Debug", "mw destructor 2");
}
