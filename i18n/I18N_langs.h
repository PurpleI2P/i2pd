/*
* Copyright (c) 2021-2022, The PurpleI2P Project
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
				const std::string& language,
				const std::map<std::string, std::string>& strings,
				const std::map<std::string, std::vector<std::string>>& plurals,
				std::function<int(int)> formula
			): m_Language (language), m_Strings (strings), m_Plurals (plurals), m_Formula (formula) { };

			// Get activated language name for webconsole
			std::string GetLanguage() const
			{
				return m_Language;
			}

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

			std::string GetPlural (const std::string& arg, const std::string& arg2, const int& n) const
			{
				const auto it = m_Plurals.find(arg2);
				if (it == m_Plurals.end()) // not found, fallback to english
				{
					return n == 1 ? arg : arg2;
				}
				else
				{
					int form = m_Formula(n);
					return it->second[form];
				}
			}

		private:
			const std::string m_Language;
			const std::map<std::string, std::string> m_Strings;
			const std::map<std::string, std::vector<std::string>> m_Plurals;
			std::function<int(int)> m_Formula;
	};

	struct langData
	{
		std::string LocaleName; // localized name
		std::string ShortCode;  // short language code, like "en"
		std::function<std::shared_ptr<const i2p::i18n::Locale> (void)> LocaleFunc;
	};

	// Add localization here with language name as namespace
	namespace afrikaans { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace armenian  { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace english   { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace french    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace german    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace russian   { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace turkmen   { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace ukrainian { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace uzbek     { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }

	/**
	 * That map contains international language name lower-case, name in it's language and it's code
	 */
	static std::map<std::string, langData> languages
	{
		{ "afrikaans", {"Afrikaans", "af", i2p::i18n::afrikaans::GetLocale} },
		{ "armenian", {"հայերէն", "hy", i2p::i18n::armenian::GetLocale} },
		{ "english", {"English", "en", i2p::i18n::english::GetLocale} },
		{ "french", {"Français", "fr", i2p::i18n::french::GetLocale} },
		{ "german", {"Deutsch", "de", i2p::i18n::german::GetLocale} },
		{ "russian", {"русский язык", "ru", i2p::i18n::russian::GetLocale} },
		{ "turkmen", {"türkmen dili", "tk", i2p::i18n::turkmen::GetLocale} },
		{ "ukrainian", {"украї́нська мо́ва", "uk", i2p::i18n::ukrainian::GetLocale} },
		{ "uzbek", {"Oʻzbek", "uz", i2p::i18n::uzbek::GetLocale} },
	};

} // i18n
} // i2p

#endif // __I18N_LANGS_H__
