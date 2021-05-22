#include <map>
#include <vector>
#include <string>

// Russian localization file

namespace i2p {
namespace i18n {
namespace russian { // language

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	int plural (int n) {
		return n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2;
	}

	static std::map<std::string, std::string> strings
	{
		{"Enabled", "Включено"},
		{"Disabled", "Выключено"}
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"days",    {"день", "дня", "дней"}},
		{"hours",   {"час", "часа", "часов"}},
		{"minutes", {"минута", "минуты", "минут"}},
		{"seconds", {"секунда", "секунды", "секунд"}}
	};

	std::string GetString (std::string arg)
	{
		auto it = strings.find(arg);
		if (it == strings.end())
		{
			return arg;
		} else {
			return it->second;
		}
	}

	std::string GetPlural (std::string arg, int n)
	{
		auto it = plurals.find(arg);
		if (it == plurals.end())
		{
			return arg;
		} else {
			int form = plural(n);
			return it->second[form];
		}
	}

} // language
} // i18n
} // i2p
