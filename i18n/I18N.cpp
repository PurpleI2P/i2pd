/*
* Copyright (c) 2021-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <clocale>
#include "ClientContext.h"
#include "I18N_langs.h"
#include "I18N.h"

namespace i2p
{
namespace i18n
{
	void SetLanguage(const std::string &lang)
	{
		const auto it = i2p::i18n::languages.find(lang);
		if (it == i2p::i18n::languages.end()) // fallback
		{
			i2p::client::context.SetLanguage (i2p::i18n::english::GetLocale());
			setlocale(LC_NUMERIC, "english");
		}
		else
		{
			i2p::client::context.SetLanguage (it->second.LocaleFunc());
			setlocale(LC_NUMERIC, lang.c_str()); // set decimal point based on language
		}
	}

	std::string translate (const std::string& arg)
	{
		return i2p::client::context.GetLanguage ()->GetString (arg);
	}

	std::string translate (const std::string& arg, const std::string& arg2, const int& n)
	{
		return i2p::client::context.GetLanguage ()->GetPlural (arg, arg2, n);
	}
} // i18n
} // i2p
