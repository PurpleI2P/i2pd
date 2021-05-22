#include <map>
#include <vector>
#include <string>

// Russian localization file

namespace i2p {
namespace i18n {
namespace english { // language

	// See for language plural forms here:
	// https://localization-guide.readthedocs.io/en/latest/l10n/pluralforms.html
	int plural (int n) {
		return n != 1 ? 1 : 0;
	}

	static std::map<std::string, std::string> strings
	{
		{"Enabled", "Enabled"},
		{"Disabled", "Disabled"}
	};

	static std::map<std::string, std::vector<std::string>> plurals
	{
		{"days",    {"day", "days"}},
		{"hours",   {"hour", "hours"}},
		{"minutes", {"minute", "minutes"}},
		{"seconds", {"second", "seconds"}}
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
