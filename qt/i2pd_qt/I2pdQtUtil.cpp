#include "I2pdQtUtil.h"

bool isValidSingleLine(QLineEdit* widget, WrongInputPageEnum inputPage, MainWindow* mainWindow) {
    bool correct = !widget->text().contains(QRegularExpression("[\r\n]"), nullptr);
    if(!correct) {
        mainWindow->highlightWrongInput(
                    QApplication::tr("Single line input expected, but it's multiline"),
                    inputPage,
                    widget);
    }
    return correct;
}
