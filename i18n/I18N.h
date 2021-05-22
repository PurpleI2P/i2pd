/*
* Copyright (c) 2021, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef __I18N_H__
#define __I18N_H__

namespace i2p {
namespace i18n {

	namespace russian {
		std::string GetString (std::string arg);
		std::string GetPlural (std::string arg, int n);
	}

	std::string translate (std::string arg)
	{
		return i2p::i18n::russian::GetString (arg);
	}

	template<typename inttype>
	std::string translate (std::string arg, inttype&& n)
	{
		return i2p::i18n::russian::GetPlural (arg, (int) n);
	}

} // i18n
} // i2p

template<typename... TArgs>
std::string tr (TArgs&&... args) {
	return i2p::i18n::translate(std::forward<TArgs>(args)...);
}

#endif // __I18N_H__
