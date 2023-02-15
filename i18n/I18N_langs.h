/*
* Copyright (c) 2021-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef __I18N_LANGS_H__
#define __I18N_LANGS_H__

#include "I18N.h"

namespace i2p
{
namespace i18n
{
	struct langData
	{
		std::string LocaleName; // localized name
		std::string ShortCode;  // short language code, like "en"
		std::function<std::shared_ptr<const i2p::i18n::Locale> (void)> LocaleFunc;
	};

	// Add localization here with language name as namespace
	namespace afrikaans  { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace armenian   { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace chinese    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace czech      { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace english    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace french     { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace german     { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace italian    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace polish     { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace portuguese { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace russian    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace spanish    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace swedish    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace turkish    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace turkmen    { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace ukrainian  { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }
	namespace uzbek      { std::shared_ptr<const i2p::i18n::Locale> GetLocale (); }

	/**
	 * That map contains international language name lower-case, name in it's language and it's code
	 */
	static std::map<std::string, langData> languages
	{
		{ "afrikaans", {"Afrikaans", "af", i2p::i18n::afrikaans::GetLocale} },
		{ "armenian", {"hայերէն", "hy", i2p::i18n::armenian::GetLocale} },
		{ "chinese", {"简体字", "zh-CN", i2p::i18n::chinese::GetLocale} },
		{ "czech", {"čeština", "cs", i2p::i18n::czech::GetLocale} },
		{ "english", {"English", "en", i2p::i18n::english::GetLocale} },
		{ "french", {"Français", "fr", i2p::i18n::french::GetLocale} },
		{ "german", {"Deutsch", "de", i2p::i18n::german::GetLocale} },
		{ "italian", {"Italiano", "it", i2p::i18n::italian::GetLocale} },
		{ "polish", {"Polski", "pl", i2p::i18n::polish::GetLocale} },
		{ "portuguese", {"Português", "pt", i2p::i18n::portuguese::GetLocale} },
		{ "russian", {"Русский язык", "ru", i2p::i18n::russian::GetLocale} },
		{ "spanish", {"Español", "es", i2p::i18n::spanish::GetLocale} },
		{ "swedish", {"Svenska", "sv", i2p::i18n::swedish::GetLocale} },
		{ "turkish", {"Türk dili", "tr", i2p::i18n::turkish::GetLocale} },
		{ "turkmen", {"Türkmen dili", "tk", i2p::i18n::turkmen::GetLocale} },
		{ "ukrainian", {"Украї́нська мо́ва", "uk", i2p::i18n::ukrainian::GetLocale} },
		{ "uzbek", {"Oʻzbek", "uz", i2p::i18n::uzbek::GetLocale} },
	};

} // i18n
} // i2p

#endif // __I18N_LANGS_H__
