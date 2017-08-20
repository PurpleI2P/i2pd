#ifndef TEXTBROWSERTWEAKED1_H
#define TEXTBROWSERTWEAKED1_H

#include <QTextBrowser>
#include <QUrl>

class TextBrowserTweaked1 : public QTextBrowser
{
    Q_OBJECT

public:
    TextBrowserTweaked1(QWidget * parent);
    //virtual void setSource(const QUrl & url);

signals:
    void mouseReleased();
    //void navigatedTo(const QUrl & link);

protected:
    void mouseReleaseEvent(QMouseEvent *event) {
        QTextBrowser::mouseReleaseEvent(event);
        emit mouseReleased();
    }
};

#endif // TEXTBROWSERTWEAKED1_H
