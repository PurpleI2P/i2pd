/*
* Copyright (c) 2021, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef __I18N_LANGS_H__
#define __I18N_LANGS_H__

namespace i2p
{
namespace i18n
{
	class Locale
	{
		public:
			Locale (
				const std::map<std::string, std::string>& strings,
				const std::map<std::string, std::vector<std::string>>& plurals,
				std::function<int(int)> formula
			): m_Strings (strings), m_Plurals (plurals), m_Formula (formula) { };

			std::string GetString (const std::string& arg) const
			{
				const auto it = m_Strings.find(arg);
				if (it == m_Strings.end())
				{
					return arg;
				}
				else
				{
					return it->second;
				}
			}

			std::string GetPlural (const std::string& arg, const int& n) const
			{
				const auto it = m_Plurals.find(arg);
				if (it == m_Plurals.end())
				{
					return arg;
				}
				else
				{
					int form = m_Formula(n);
					return it->second[form];
				}
			}

		private:
			const std::map<std::string, std::string> m_Strings;
			const std::map<std::string, std::vector<std::string>> m_Plurals;
			std::function<int(int)> m_Formula;
	};

	// Add localization here with language name as namespace
	namespace english { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace russian { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace ukrainian { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }

} // i18n
} // i2p

#endif // __I18N_LANGS_H__
