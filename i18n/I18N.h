/*
* Copyright (c) 2021-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef __I18N_H__
#define __I18N_H__

#include "ClientContext.h"

namespace i2p
{
namespace i18n
{
	inline void SetLanguage(const std::string &lang)
	{
		const auto it = i2p::i18n::languages.find(lang);
		if (it == i2p::i18n::languages.end()) // fallback
			i2p::client::context.SetLanguage (i2p::i18n::english::GetLocale());
		else
			i2p::client::context.SetLanguage (it->second.LocaleFunc());
	}

	inline std::string translate (const std::string& arg)
	{
		return i2p::client::context.GetLanguage ()->GetString (arg);
	}

	inline std::string translate (const std::string& arg, const std::string& arg2, const int& n)
	{
		return i2p::client::context.GetLanguage ()->GetPlural (arg, arg2, n);
	}
} // i18n
} // i2p

template<typename... TArgs>
std::string tr (TArgs&&... args)
{
	return i2p::i18n::translate(std::forward<TArgs>(args)...);
}

#endif // __I18N_H__
