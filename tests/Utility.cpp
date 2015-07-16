#include <boost/test/unit_test.hpp>
#include "../util.h"

BOOST_AUTO_TEST_SUITE(UtilityTests)

using namespace i2p::util::http;

BOOST_AUTO_TEST_CASE(DecodeEmptyUrl)
{
    BOOST_CHECK_EQUAL(urlDecode(""), "");
}

BOOST_AUTO_TEST_CASE(DecodeUrl)
{
    BOOST_CHECK_EQUAL(urlDecode("%20"), " ");
}


BOOST_AUTO_TEST_SUITE_END()
