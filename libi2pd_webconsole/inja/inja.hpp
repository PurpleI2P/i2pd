/*
  ___        _          Version 3.3
 |_ _|_ __  (_) __ _    https://github.com/pantor/inja
  | || '_ \ | |/ _` |   Licensed under the MIT License <http://opensource.org/licenses/MIT>.
  | || | | || | (_| |
 |___|_| |_|/ |\__,_|   Copyright (c) 2018-2021 Lars Berscheid
          |__/
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef INCLUDE_INJA_INJA_HPP_
#define INCLUDE_INJA_INJA_HPP_

//#include <nlohmann/json.hpp>
#include "../nlohmann/json.hpp"

namespace inja {
#ifndef INJA_DATA_TYPE
using json = nlohmann::json;
#else
using json = INJA_DATA_TYPE;
#endif
} // namespace inja

#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) && !defined(INJA_NOEXCEPTION)
#ifndef INJA_THROW
#define INJA_THROW(exception) throw exception
#endif
#else
#include <cstdlib>
#ifndef INJA_THROW
#define INJA_THROW(exception)                                                                                                                                  \
  std::abort();                                                                                                                                                \
  std::ignore = exception
#endif
#ifndef INJA_NOEXCEPTION
#define INJA_NOEXCEPTION
#endif
#endif

#include "environment.hpp"
#include "exceptions.hpp"
#include "parser.hpp"
#include "renderer.hpp"
#include "template.hpp"

#endif // INCLUDE_INJA_INJA_HPP_
