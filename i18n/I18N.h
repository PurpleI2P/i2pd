/*
* Copyright (c) 2021, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef __I18N_H__
#define __I18N_H__

#include "RouterContext.h"

namespace i2p
{
namespace i18n
{
	inline void SetLanguage(const std::string &lang)
	{
		if (!lang.compare("russian"))
			i2p::context.SetLanguage (i2p::i18n::russian::GetLocale());
		else if (!lang.compare("turkmen"))
			i2p::context.SetLanguage (i2p::i18n::turkmen::GetLocale());
		else if (!lang.compare("ukrainian"))
			i2p::context.SetLanguage (i2p::i18n::ukrainian::GetLocale());
		else // fallback
			i2p::context.SetLanguage (i2p::i18n::english::GetLocale());
	}

	inline std::string translate (const std::string& arg)
	{
		return i2p::context.GetLanguage ()->GetString (arg);
	}

	inline std::string translate (const std::string& arg, const int& n)
	{
		return i2p::context.GetLanguage ()->GetPlural (arg, n);
	}
} // i18n
} // i2p

template<typename... TArgs>
std::string tr (TArgs&&... args)
{
	return i2p::i18n::translate(std::forward<TArgs>(args)...);
}

#endif // __I18N_H__
