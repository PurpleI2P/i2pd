/*
* Copyright (c) 2023, The PurpleI2P Project
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

// Polish localization file

namespace i2p
{
namespace i18n
{
namespace polish // language namespace
{
	// language name in lowercase
	static std::string language = "polish";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return (n == 1 ? 0 : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? 1 : 2);
	}

	static std::map<std::string, std::string> strings
	{
		{"building", "Kompilowanie"},
		{"failed", "nieudane"},
		{"expiring", "wygasający"},
		{"established", "ustanowiony"},
		{"Main page", "Strona główna"},
		{"Router commands", "Komendy routera"},
		{"Tunnels", "Tunele"},
		{"OK", "Ok"},
		{"Uptime", "Czas pracy"},
		{"Sent", "Wysłane"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"", {"", "", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
