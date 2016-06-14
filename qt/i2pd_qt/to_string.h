#ifndef TO_STRING_H
#define TO_STRING_H

#include <string>
#include <sstream>

namespace tostr {
template <typename T>
std::string to_string(T value)
{
    std::ostringstream os ;
    os << value ;
    return os.str() ;
}
}

using namespace tostr;

#endif // TO_STRING_H
