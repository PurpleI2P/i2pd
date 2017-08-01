#ifndef TEXTBROWSERTWEAKED1_H
#define TEXTBROWSERTWEAKED1_H

#include <QTextBrowser>

class TextBrowserTweaked1 : public QTextBrowser
{
    Q_OBJECT

public:
    TextBrowserTweaked1();

signals:
    void mouseReleased();

protected:
    void mouseReleaseEvent(QMouseEvent *event) {
        emit mouseReleased();
    }
};

#endif // TEXTBROWSERTWEAKED1_H
