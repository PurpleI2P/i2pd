/*
* Copyright (c) 2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <map>
#include <vector>
#include <string>
#include <memory>
#include "I18N.h"

// Hebrew localization file

namespace i2p
{
namespace i18n
{
namespace hebrew // language namespace
{
	// language name in lowercase
	static std::string language = "hebrew";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n % 100 == 1 ? 0 : n % 100 == 2 ? 1 : n % 100 == 3 || n % 100 == 4 ? 2 : 3;
	}

	// Right to Left language?
	static bool rtl = true;

	static const LocaleStrings strings
	{
		{"%.2f KiB", "%.2f קי״ב"},
		{"%.2f MiB", "%.2f מי״ב"},
		{"%.2f GiB", "%.2f קי״ב"},
		{"Purple I2P Webconsole", "קונסולת Purple I2P"},
		{"<b>i2pd</b> webconsole", "קונסולת <b>i2pd</b>"},
		{"Main page", "עמוד ראשי"},
		{"Router commands", "פקודות נתב"},
		{"Local Destinations", "יעדים מקומיים"},
		{"Tunnels", "מנהרות"},
		{"Transit Tunnels", "מנהרות מעבר"},
		{"Transports", "מובילים"},
		{"I2P tunnels", "מנהרות I2P"},
		{"SAM sessions", "הפעלות SAM"},
		{"Unknown", "לא מוכר"},
		{"Proxy", "פרוקסי"},
		{"Mesh", "סיבוך"},
		{"Clock skew", "לכסון שעון"},
		{"Offline", "לא מקוון"},
		{"Symmetric NAT", "NAT סימטרי"},
		{"Full cone NAT", "NAT חסום לחלוטין"},
		{"No Descriptors", "אין מתארים"},
		{"Uptime", "זמן הפעלה"},
		{"Network status", "מצב רשת תקשורת"},
		{"Network status v6", "מצב רשת תקשורת v6"},
		{"Stopping in", "מפסיק בעוד"},
		{"Family", "משפחה"},
		{"Tunnel creation success rate", "שיעור הצלחה של יצירת מנהרות"},
		{"Total tunnel creation success rate", "שיעור הצלחה כולל של יצירת מנהרות"},
		{"Received", "נתקבל"},
		{"%.2f KiB/s", "%.2f קי״ב/ש"},
		{"Sent", "נשלח"},
		{"Transit", "מעבר"},
		{"Data path", "נתיב מידע"},
		{"Hidden content. Press on text to see.", "תוכן מוסתר. לחץ על הטקסט כדי לראותו."},
		{"Router Ident", "מזהה נתב"},
		{"Router Family", "משפחת נתב"},
		{"Version", "גרסא"},
		{"Our external address", "הכתובת החיצונית שלנו"},
		{"supported", "נתמך"},
		{"Routers", "נתבים"},
		{"Client Tunnels", "מנהרות לקוח"},
		{"Services", "שירותים"},
		{"Enabled", "מאופשר"},
		{"Disabled", "מנוטרל"},
		{"Encrypted B33 address", "כתובת B33 מוצפנת"},
		{"Address registration line", "שורת רישום כתובת"},
		{"Domain", "תחום"},
		{"Generate", "צור"},
		{"<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.", "<b>הערה</b> מחרוזת תוצאה יכולה להיות מועילה רק לצורך רישום תחומים 2LD (example.i2p). לשם רישום תתי-תחום עליך להיוועץ עם i2pd-tools."},
		{"Address", "כתובת"},
		{"Type", "טיפוס"},
		{"Expire LeaseSet", "פקיעת LeaseSet"},
		{"Inbound tunnels", "מנהרות פנימיות"},
		{"%dms", "מילישניות %d"},
		{"Outbound tunnels", "מנהרות חיצוניות"},
		{"Tags", "תוויות"},
		{"Incoming", "נכנס"},
		{"Outgoing", "יוצא"},
		{"Destination", "יעד"},
		{"Amount", "כמות"},
		{"Incoming Tags", "תוויות נכנסות"},
		{"Tags sessions", "הפעלות תוויות"},
		{"Status", "מצב"},
		{"Local Destination", "יעד מקומי"},
		{"Streams", "זרמים"},
		{"Close stream", "סגור זרם"},
		{"Such destination is not found", "יעד כזה לא נמצא"},
		{"I2CP session not found", "הפעלת I2CP לא נמצאה"},
		{"I2CP is not enabled", "I2CP לא מאופשר"},
		{"Invalid", "לא תקין"},
		{"Store type", "טיפוס אחסון"},
		{"Expires", "פוקע"},
		{"Non Expired Leases", "חכירות בלתי פקיעות"},
		{"Gateway", "שער-דרך"},
		{"TunnelID", "מזהה מנהרה"},
		{"EndDate", "תאריך סיום"},
		{"floodfill mode is disabled", "מצב floodfill הינו מנוטרל"},
		{"Queue size", "גודל תור"},
		{"Run peer test", "הרץ בדיקת עמית"},
		{"Reload tunnels configuration", "טען מחדש תצורת מנהרות"},
		{"Decline transit tunnels", "דחה מנהרות מעבר"},
		{"Accept transit tunnels", "קבל מנהרות מעבר"},
		{"Cancel graceful shutdown", "בטל כיבוי עדין"},
		{"Start graceful shutdown", "התחל כיבוי עדין"},
		{"Force shutdown", "כפה כיבוי"},
		{"Reload external CSS styles", "טען מחדש סגנונות CSS חיצוניים"},
		{"<b>Note:</b> any action done here are not persistent and not changes your config files.", "<b>הערה</b> כל פעולה אשר מבוצעת כאן אינה המשכית ולא משנה את קובצי התצורה שלך."},
		{"Logging level", "דרגת רישום יומן"},
		{"Transit tunnels limit", "מגבלת מנהרות מעבר"},
		{"Change", "שנה"},
		{"Change language", "שנה שפה"},
		{"no transit tunnels currently built", "אין מנהרות מעבר אשר בנויות כעת"},
		{"SAM disabled", "SAM מנוטרל"},
		{"no sessions currently running", "אין הפעלה אשר מורצת כעת"},
		{"SAM session not found", "הפעלת SAM לא נמצאה"},
		{"SAM Session", "הפעלת SAM"},
		{"Server Tunnels", "מנהרות שרת"},
		{"Unknown page", "עמוד לא מוכר"},
		{"Invalid token", "סימן לא תקין"},
		{"SUCCESS", "הצלחה"},
		{"Stream closed", "זרם סגור"},
		{"Stream not found or already was closed", "זרם לא נמצא או שהוא היה כבר סגור"},
		{"Destination not found", "יעד לא נמצא"},
		{"StreamID can't be null", "מזהה זרם (StreamID) לא יכול להיות אפסי"},
		{"Return to destination page", "חזור לעמוד יעד"},
		{"You will be redirected in %d seconds", "אתה תכוון מחדש בעוד %d שניות"},
		{"LeaseSet expiration time updated", "זמן פקיעה של LeaseSet עודכן"},
		{"LeaseSet is not found or already expired", "LeaseSet אינו נמצא או שהוא כבר פקע"},
		{"Transit tunnels count must not exceed %d", "אסור לספירת מנהרות מעבר לעלות על %d"},
		{"Back to commands list", "חזור לרשימת פקודות"},
		{"Register at reg.i2p", "הירשם באתר reg.i2p"},
		{"Description", "תיאור"},
		{"A bit information about service on domain", "מידע אודות שירות על תחום"},
		{"Submit", "שלח"},
		{"Domain can't end with .b32.i2p", "תחום לא יכול להסתיים עם &#8206;.b32.i2p"},
		{"Domain must end with .i2p", "תחום חייב להסתיים עם &#8206;.i2p"},
		{"Unknown command", "פקודה לא מוכרת"},
		{"Command accepted", "פקודה נתקבלה"},
		{"Proxy error", "שגיאת פרוקסי"},
		{"Proxy info", "מידע פרוקסי"},
		{"Proxy error: Host not found", "שגיאת פרוקסי: מארח לא נמצא"},
		{"Remote host not found in router's addressbook", "ארח מרוחק לא נמצא בתוך הפנקס כתובות של הנתב"},
		{"You may try to find this host on jump services below", "באפשרותך לנסות למצוא את מארח זה דרך שירותי קפיצה להלן"},
		{"Invalid request", "בקשה לא תקינה"},
		{"Proxy unable to parse your request", "פרוקסי לא מסוגל לנתח את בקשתך"},
		{"Addresshelper is not supported", "סייען-כתובות אינו נתמך"},
		{"Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "מארח %s is <font color=red>כבר נמצא בפנקס כתובות של הנתב</font>. <b>זהירות: מקור URL זה עלול להזיק!</b> לחץ כאן כדי לעדכן מרשם: <a href=\"%s%s%s&update=true\">המשך</a>."},
		{"Addresshelper forced update rejected", "אילוץ עדכון של סייען-כתובות נדחה"},
		{"To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.", "Tכדי להוסיף את מארח <b>%s</b> לפנקס כתובות של הנתב: <a href=\"%s%s%s\">המשך</a>."},
		{"Addresshelper request", "בקשת סייען-כתובות"},
		{"Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.", "מארח %s נתווסף לסייען-כתובות של הנתב דרך סייען. לחץ כאן כדי proceed: <a href=\"%s\">המשך</a>."},
		{"Addresshelper adding", "הוספת סייען-כתובות"},
		{"Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.", "מארח %s <font color=red>כבר נמצא בספר כתובות של הנתב</font>. לחץ כאן כדי לעדכן מרשם: <a href=\"%s%s%s&update=true\">המשך</a>."},
		{"Addresshelper update", "עדכון סייען-כתובות"},
		{"Invalid request URI", "בקשת URI לא תקינה"},
		{"Can't detect destination host from request", "לא יכול לאתר יעד מארח מתוך בקשה"},
		{"Host %s is not inside I2P network, but outproxy is not enabled", "מארח %s לא נמצא בתוך רשת I2P, אולם outproxy אינו מאופשר"},
		{"Hostname is too long", "שם-מארח הינו ארוך מדי"},
		{"Cannot negotiate with SOCKS proxy", "לא מסוגל להסדיר פרוקסי SOCKS"},
		{"CONNECT error", "שגיאת חיבור"},
		{"Failed to connect", "נכשל להתחבר"},
		{"SOCKS proxy error", "שגיאת פרוקסי SOCKS"},
		{"No reply from SOCKS proxy", "אין מענה מתוך פרוקסי SOCKS"},
		{"Cannot connect", "לא מסוגל להתחבר"},
		{"Host is down", "מארח הינו מושבת"},
		{"Can't create connection to requested host, it may be down. Please try again later.", "לא יכול ליצור חיבור למארח מבוקש, המארח עשוי להיות מושבת. אנא נסה שוב מאוחר יותר."},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"יום %d", "יומיים", "ימים %d", "ימים %d"}},
		{"%d hours", {"שעה %d", "שעתיים", "שעות %d", "שעות %d"}},
		{"%d minutes", {"דקה %d", "שתי דקות", "דקות %d", "דקות %d"}},
		{"%d seconds", {"שניה %d", "שתי שניות", "שניות %d", "שניות %d"}},
		{"", {"", "", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, rtl, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
