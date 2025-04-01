/*
* Copyright (c) 2021-2025, The PurpleI2P Project
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
		return n != 1 ? 1 : 0;
	}

	static const LocaleStrings strings
	{
		{"failed", "נכשל"},
		{"unknown", "לא מוכר"},
		{"Tunnels", "מנהרות"},
		{"I2P tunnels", "מנהרות I2P"},
		{"SAM sessions", "הרצות SAM"},
		{"OK", "אישור"},
		{"Testing", "בדיקה"},
		{"Firewalled", "מאחורי חומת-אש"},
		{"Unknown", "לא מוכר"},
		{"Error", "שגיאה"},
		{"Offline", "לא מקוון"},
		{"Uptime", "זמן פעילות"},
		{"Network status", "מצב רשת תקשורת"},
		{"Network status v6", "מצב רשת תקשורת v6"},
		{"Family", "משפחה"},
		{"Received", "נתקבל"},
		{"Sent", "נשלח"},
		{"Hidden content. Press on text to see.", "תוכן מוסתר. לחץ על טקסט זה כדי לראותו."},
		{"Router Ident", "מזהה נתב"},
		{"Router Family", "משפחת נתב"},
		{"Enabled", "מאופשר"},
		{"Disabled", "מנוטרל"},
		{"Change", "שנה"},
		{"Change language", "שנה שפה"},
		{"Description", "תיאור"},
		{"Submit", "אשר"},
		{"Proxy error", "שגיאת פרוקסי"},
		{"Host", "מארח"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"יום %d", "%d ימים"}},
		{"%d hours", {"שעה %d", "%d שעות"}},
		{"%d minutes", {"דקה %d", "%d דקות"}},
		{"%d seconds", {"שניה %d", "%d שניות"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
