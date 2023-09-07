/*
* Copyright (c) 2021, The PurpleI2P Project
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

// Afrikaans localization file

namespace i2p
{
namespace i18n
{
namespace afrikaans // language namespace
{
	// language name in lowercase
	static std::string language = "afrikaans";

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	static int plural (int n) {
		return n != 1 ? 1 : 0;
	}

	static std::map<std::string, std::string> strings
	{
		{"failed", "Het misluk"},
		{"unknown", "onbekend"},
		{"Tunnels", "Tonnels"},
		{"I2P tunnels", "I2P tonnels"},
		{"SAM sessions", "SAM sessies"},
		{"OK", "LEKKER"},
		{"Testing", "Besig om te toets"},
		{"Firewalled", "Vuurmuur'd"},
		{"Unknown", "Onbekend"},
		{"Error", "Fout"},
		{"Offline", "Aflyn"},
		{"Uptime", "Optyd"},
		{"Network status", "Netwerk status"},
		{"Network status v6", "Netwerk status v6"},
		{"Family", "Familie"},
		{"Received", "Ontvang"},
		{"Sent", "Gestuur"},
		{"Hidden content. Press on text to see.", "Hidden content. Druk om te sien."},
		{"Router Ident", "Router Ident"},
		{"Router Family", "Router Familie"},
		{"Enabled", "Geaktiveer"},
		{"Disabled", "Gedeaktiveer"},
		{"Change", "Verander"},
		{"Change language", "Verander taal"},
		{"Description", "Beskrywing"},
		{"Submit", "Stuur"},
		{"Proxy error", "Proxy-fout"},
		{"Host", "Gasheer"},
		{"", ""},
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"%d days", {"%d dag", "%d dae"}},
		{"%d hours", {"%d uur", "%d ure"}},
		{"%d minutes", {"%d minuut", "%d minute"}},
		{"%d seconds", {"%d seconde", "%d sekondes"}},
		{"", {"", ""}},
	};

	std::shared_ptr<const i2p::i18n::Locale> GetLocale()
	{
		return std::make_shared<i2p::i18n::Locale>(language, strings, plurals, [] (int n)->int { return plural(n); });
	}

} // language
} // i18n
} // i2p
