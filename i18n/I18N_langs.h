/*
* Copyright (c) 2021, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef __I18N_LANGS_H__
#define __I18N_LANGS_H__

namespace i2p {

enum Lang {
	eEnglish = 0,
	eRussian
};

namespace i18n {

	namespace english {
		std::string GetString (std::string arg);
		std::string GetPlural (std::string arg, int n);
	}

	namespace russian {
		std::string GetString (std::string arg);
		std::string GetPlural (std::string arg, int n);
	}

} // i18n
} // i2p

#endif // __I18N_LANGS_H__
