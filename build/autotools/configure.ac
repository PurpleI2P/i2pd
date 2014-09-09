AC_PREREQ([2.69])
AC_INIT([i2pd], [0.0.0],
	[https://track.privacysolutions.no/projects/i2pd/issues])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([I2NPProtocol.cpp])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Check for C++11
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
AX_CXX_COMPILE_STDCXX_11([],[mandatory])

# Set platform specific flags
if test "$(uname -s)" = "Darwin"
then
	CXXFLAGS="-DCRYPTOPP_DISABLE_ASM -DAESNI ${CXXFLAGS}"

elif test "$(uname -s)" = "Linux"
then
	if test -n "$(grep aes /proc/cpuinfo)"
	then
		CXXFLAGS="-DAESNI ${CXXFLAGS}"
	fi
else
	# emtpy
	true
fi

# Checks for libraries.
AC_SEARCH_LIBS([s_sosemanukMulTables], [cryptopp],
	       [], [AC_MSG_ERROR([Unable to find crypto++])])

m4_include([m4/ax_boost_base.m4])
m4_include([m4/ax_boost_date_time.m4])
m4_include([m4/ax_boost_filesystem.m4])
m4_include([m4/ax_boost_program_options.m4])
m4_include([m4/ax_boost_regex.m4])
m4_include([m4/ax_boost_system.m4])
AX_BOOST_BASE([1.46])
AX_BOOST_DATE_TIME
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS
AX_BOOST_REGEX
AX_BOOST_SYSTEM

m4_include([m4/ax_pthread.m4])
AX_PTHREAD()

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([memchr memset setlocale socket strstr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
