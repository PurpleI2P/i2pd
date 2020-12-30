#include "AboutDialog.h"
#include "ui_AboutDialog.h"
#include <QDebug>
#include "version.h"
#include "BuildDateTimeQt.h"

AboutDialog::AboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    ui->i2pdVersionLabel->setText(I2PD_VERSION);
    ui->i2pVersionLabel->setText(I2P_VERSION);
    ui->buildDateTimeLabel->setText(BUILD_DATE_TIME_QT);
    ui->vcsCommitInfoLabel->setText(VCS_COMMIT_INFO);
}

AboutDialog::~AboutDialog()
{
    delete ui;
}
