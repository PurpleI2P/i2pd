cmake_minimum_required(VERSION 3.7)

if(${CMAKE_VERSION} VERSION_LESS 3.22)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
else()
  cmake_policy(VERSION 3.22)
endif()

# for debugging
#set(CMAKE_VERBOSE_MAKEFILE on)

# paths
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules")
set(CMAKE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

set(LIBI2PD_SRC_DIR ${CMAKE_SOURCE_DIR}/libi2pd)
set(LIBI2PD_CLIENT_SRC_DIR ${CMAKE_SOURCE_DIR}/libi2pd_client)
set(LANG_SRC_DIR ${CMAKE_SOURCE_DIR}/i18n)
set(DAEMON_SRC_DIR ${CMAKE_SOURCE_DIR}/daemon)

include(Version)
set_version("${LIBI2PD_SRC_DIR}/version.h" PROJECT_VERSION)

project(
  i2pd
  VERSION ${PROJECT_VERSION}
  HOMEPAGE_URL "https://i2pd.website/"
  LANGUAGES C CXX
)

# configurable options
option(WITH_AESNI           "Use AES-NI instructions set"             ON)
option(WITH_HARDENING       "Use hardening compiler flags"            OFF)
option(WITH_LIBRARY         "Build library"                           ON)
option(WITH_BINARY          "Build binary"                            ON)
option(WITH_STATIC          "Static build"                            OFF)
option(WITH_UPNP            "Include support for UPnP client"         OFF)
option(WITH_GIT_VERSION     "Use git commit info as version"          OFF)
option(WITH_ADDRSANITIZER   "Build with address sanitizer unix only"  OFF)
option(WITH_THREADSANITIZER "Build with thread sanitizer unix only"   OFF)
option(BUILD_TESTING        "Build tests"                             OFF)

IF(BUILD_TESTING)
  enable_testing()
ENDIF()

# Handle paths nicely
include(GNUInstallDirs)

# Architecture
include(TargetArch)
target_architecture(ARCHITECTURE)

include(CheckAtomic)

if(WITH_STATIC)
  if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()
endif()

include_directories(${LIBI2PD_SRC_DIR})
FILE(GLOB LIBI2PD_SRC ${LIBI2PD_SRC_DIR}/*.cpp)
add_library(libi2pd ${LIBI2PD_SRC})
set_target_properties(libi2pd PROPERTIES PREFIX "")

if(WITH_LIBRARY)
  install(TARGETS libi2pd
    EXPORT libi2pd
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT Libraries)
endif()

include_directories(${LIBI2PD_CLIENT_SRC_DIR})
FILE(GLOB CLIENT_SRC ${LIBI2PD_CLIENT_SRC_DIR}/*.cpp)
add_library(libi2pdclient ${CLIENT_SRC})
set_target_properties(libi2pdclient PROPERTIES PREFIX "")

if(WITH_LIBRARY)
  install(TARGETS libi2pdclient
    EXPORT libi2pdclient
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT Libraries)
endif()

include_directories(${LANG_SRC_DIR})
FILE(GLOB LANG_SRC ${LANG_SRC_DIR}/*.cpp)
add_library(libi2pdlang ${LANG_SRC})
set_target_properties(libi2pdlang PROPERTIES PREFIX "")

if(WITH_LIBRARY)
  install(TARGETS libi2pdlang
    EXPORT libi2pdlang
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT Libraries)
endif()

include_directories(${DAEMON_SRC_DIR})

set(DAEMON_SRC
  "${DAEMON_SRC_DIR}/Daemon.cpp"
  "${DAEMON_SRC_DIR}/HTTPServer.cpp"
  "${DAEMON_SRC_DIR}/I2PControl.cpp"
  "${DAEMON_SRC_DIR}/I2PControlHandlers.cpp"
  "${DAEMON_SRC_DIR}/i2pd.cpp"
  "${DAEMON_SRC_DIR}/UPnP.cpp"
)

if(WIN32)
  set(WIN32_SRC_DIR ${CMAKE_SOURCE_DIR}/Win32)
  include_directories(${WIN32_SRC_DIR})

  list(APPEND DAEMON_SRC
    "${WIN32_SRC_DIR}/DaemonWin32.cpp"
    "${WIN32_SRC_DIR}/Win32App.cpp"
    "${WIN32_SRC_DIR}/Win32Service.cpp"
    "${WIN32_SRC_DIR}/Win32NetState.cpp"
  )

  file(GLOB WIN32_RC ${WIN32_SRC_DIR}/*.rc)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32_APP -DWIN32_LEAN_AND_MEAN -DNOMINMAX")

endif()

if(WITH_UPNP)
  add_definitions(-DUSE_UPNP)
endif()

if(WITH_GIT_VERSION)
  include(GetGitRevisionDescription)
  git_describe(GIT_VERSION)
  add_definitions(-DGITVER=${GIT_VERSION})
endif()

if(APPLE)
  add_definitions(-DMAC_OSX)
endif()

if(HAIKU)
  add_definitions(-D_DEFAULT_SOURCE -D_GNU_SOURCE)
endif()

if(MSVC)
  add_definitions(-DWINVER=0x0600)
  add_definitions(-D_WIN32_WINNT=0x0600)
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch -Wno-unused-parameter -Wno-uninitialized")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")
  # TODO: The following is incompatible with static build and enabled hardening for OpenWRT.
  # Multiple definitions of __stack_chk_fail(libssp & libc)
  if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s")
  endif()
  set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -ffunction-sections -fdata-sections")
  set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections") # -flto is added from above
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe")
  if(WITH_HARDENING)
    add_definitions("-D_FORTIFY_SOURCE=2")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security -Werror=format-security")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector --param ssp-buffer-size=4")
  endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # more tweaks
  if(LINUX)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -stdlib=libstdc++") # required for <atomic>
    list(APPEND CMAKE_REQUIRED_LIBRARIES "stdc++") # required to link with -stdlib=libstdc++
  endif()
  if(NOT APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-const-variable -Wno-overloaded-virtual -Wno-c99-extensions")
  endif()
endif()

# compiler flags customization(by system)
if(UNIX)
  list(APPEND DAEMON_SRC "${DAEMON_SRC_DIR}/UnixDaemon.cpp")
  if(NOT(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR APPLE))
    # "'sleep_for' is not a member of 'std::this_thread'" in gcc 4.7/4.8
    add_definitions("-D_GLIBCXX_USE_NANOSLEEP=1")
  endif()
endif()

# Note: AES-NI and AVX is available on x86-based CPU's.
# Here also ARM64 implementation, but currently we don't support it.
# MSVC is not supported due to different ASM processing, so we hope OpenSSL has its own checks to run optimized code.
if(WITH_AESNI AND (ARCHITECTURE MATCHES "x86_64" OR ARCHITECTURE MATCHES "i386"))
  if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
  endif()
  add_definitions(-D__AES__)
endif()

if(WITH_ADDRSANITIZER)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

if(WITH_THREADSANITIZER)
  if(WITH_ADDRSANITIZER)
    message(FATAL_ERROR "thread sanitizer option cannot be combined with address sanitizer")
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
  endif()
endif()

if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10.0 AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 8.0) # gcc 8-9
    list(APPEND CMAKE_REQUIRED_LIBRARIES "stdc++fs")
endif()

# Use std::atomic instead of GCC builtins on macOS PowerPC:
# For more information refer to: https://github.com/PurpleI2P/i2pd/issues/1726#issuecomment-1306335111
# This has been fixed in Boost 1.81, nevertheless we retain the setting for the sake of compatibility.
if(APPLE AND CMAKE_OSX_ARCHITECTURES MATCHES "ppc")
  add_definitions(-DBOOST_SP_USE_STD_ATOMIC)
endif()

# libraries
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if(WITH_STATIC)
  if(NOT MSVC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  endif()

  set(Boost_USE_STATIC_LIBS ON)
  if(MSVC)
    set(Boost_USE_STATIC_RUNTIME ON)
  else()
    set(Boost_USE_STATIC_RUNTIME OFF)
  endif()

  if(MSVC)
    set(OPENSSL_MSVC_STATIC_RT ON)
  endif()
  set(OPENSSL_USE_STATIC_LIBS ON)

  set(ZLIB_USE_STATIC_LIBS ON)
  if(MSVC)
    set(ZLIB_NAMES zlibstatic zlibstat)
  else()
    set(ZLIB_NAMES libz zlibstatic zlibstat zlib z)
  endif()

  if(WITH_UPNP)
    set(MINIUPNPC_USE_STATIC_LIBS ON)
    add_definitions(-DMINIUPNP_STATICLIB)
  endif()

  set(BUILD_SHARED_LIBS OFF)

  if(${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
    # set(CMAKE_THREAD_LIBS_INIT "gcc_eh -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
    set(CMAKE_THREAD_LIBS_INIT "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,-u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal,-u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,-u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel")
  endif()
else()
  # TODO: Consider separate compilation for LIBI2PD_SRC for library.
  # No need in -fPIC overhead for binary if not interested in library
  # HINT: revert c266cff CMakeLists.txt: compilation speed up
  if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
  endif()
  add_definitions(-DBOOST_ATOMIC_DYN_LINK -DBOOST_SYSTEM_DYN_LINK -DBOOST_FILESYSTEM_DYN_LINK -DBOOST_PROGRAM_OPTIONS_DYN_LINK)
  if(WIN32)
    set(Boost_USE_STATIC_LIBS OFF)
    set(Boost_USE_STATIC_RUNTIME OFF)
  endif()
endif()

find_package(Boost REQUIRED COMPONENTS system filesystem program_options)
if(NOT DEFINED Boost_FOUND)
  message(SEND_ERROR "Boost is not found, or your boost version was below 1.46. Please download Boost!")
endif()

find_package(OpenSSL REQUIRED)
if(NOT DEFINED OPENSSL_FOUND)
  message(SEND_ERROR "Could not find OpenSSL. Please download and install it first!")
endif()

if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0.0")
  add_definitions(-DOPENSSL_SUPPRESS_DEPRECATED)
endif()

if(WITH_UPNP)
  find_package(MiniUPnPc REQUIRED)
  if(NOT MINIUPNPC_FOUND)
    message(SEND_ERROR "Could not find MiniUPnPc. Please download and install it first!")
  else()
    include_directories(SYSTEM ${MINIUPNPC_INCLUDE_DIR})
  endif()
endif()

find_package(ZLIB)
if(ZLIB_FOUND)
  link_directories(${ZLIB_ROOT}/lib)
endif()

# C++ standard to use, based on compiler and version of boost
if(NOT MSVC)
# check for c++20 & c++17 support
  include(CheckCXXCompilerFlag)

  if(Boost_VERSION VERSION_GREATER_EQUAL "1.83") # min boost version for c++20
    CHECK_CXX_COMPILER_FLAG("-std=c++20" CXX20_SUPPORTED)
  endif()
  CHECK_CXX_COMPILER_FLAG("-std=c++17" CXX17_SUPPORTED)
 

  if(CXX20_SUPPORTED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")
  elseif(CXX17_SUPPORTED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
  else()
    message(SEND_ERROR "C++20 nor C++17 standard not seems to be supported by compiler. Too old version?")
  endif()
endif()

# load includes
include_directories(SYSTEM ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})

# show summary
message(STATUS "---------------------------------------")
message(STATUS "Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler vendor    : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version   : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiler path      : ${CMAKE_CXX_COMPILER}")
message(STATUS "Architecture       : ${ARCHITECTURE}")
message(STATUS "Compiler flags     : ${CMAKE_CXX_FLAGS}")
message(STATUS "Install prefix:    : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Options:")
message(STATUS "  AESNI            : ${WITH_AESNI}")
message(STATUS "  HARDENING        : ${WITH_HARDENING}")
message(STATUS "  LIBRARY          : ${WITH_LIBRARY}")
message(STATUS "  BINARY           : ${WITH_BINARY}")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "  UPnP             : ${WITH_UPNP}")
if(WITH_GIT_VERSION)
message(STATUS "  GIT VERSION      : ${WITH_GIT_VERSION} (${GIT_VERSION})")
else()
message(STATUS "  GIT VERSION      : ${WITH_GIT_VERSION}")
endif()
message(STATUS "  ADDRSANITIZER    : ${WITH_ADDRSANITIZER}")
message(STATUS "  THREADSANITIZER  : ${WITH_THREADSANITIZER}")
message(STATUS "---------------------------------------")

if(WITH_BINARY)
  if(WIN32)
    add_executable("${PROJECT_NAME}" WIN32 ${DAEMON_SRC} ${WIN32_RC})
  else()
    add_executable("${PROJECT_NAME}" ${DAEMON_SRC})
  endif()

  if(WIN32)
    list(APPEND MINGW_EXTRA "wsock32" "ws2_32" "iphlpapi")
    # OpenSSL may require Crypt32 library on MSVC build, which is not added by CMake lesser than 3.21
    if(MSVC AND ${CMAKE_VERSION} VERSION_LESS 3.21)
      list(APPEND MINGW_EXTRA "crypt32")
    endif()
  endif()

  if(WITH_STATIC)
    if(NOT MSVC)
      set_target_properties("${PROJECT_NAME}" PROPERTIES LINK_FLAGS "-static")
    endif()
  endif()

  if(WITH_HARDENING AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties("${PROJECT_NAME}" PROPERTIES LINK_FLAGS "-z relro -z now")
  endif()

  # FindBoost pulls pthread for thread which is broken for static linking at least on Ubuntu 15.04
  list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
  if(${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
    list(REMOVE_AT Boost_LIBRARIES -1)
  endif()

  # synchronization library is incompatible with Windows 7
  if(WIN32)
    get_target_property(BOOSTFSLIBS Boost::filesystem INTERFACE_LINK_LIBRARIES)
    list(REMOVE_ITEM BOOSTFSLIBS synchronization)
    set_target_properties(Boost::filesystem PROPERTIES INTERFACE_LINK_LIBRARIES "${BOOSTFSLIBS}")
  endif()

  if(WITH_STATIC)
    set(DL_LIB ${CMAKE_DL_LIBS})
  endif()

  target_link_libraries("${PROJECT_NAME}" libi2pd libi2pdclient libi2pdlang ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto ${MINIUPNPC_LIBRARY} ZLIB::ZLIB Threads::Threads ${MINGW_EXTRA} ${DL_LIB} ${CMAKE_REQUIRED_LIBRARIES})

  install(TARGETS "${PROJECT_NAME}" RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
  set(APPS "\${CMAKE_INSTALL_PREFIX}/bin/${PROJECT_NAME}${CMAKE_EXECUTABLE_SUFFIX}")
  set(DIRS "${Boost_LIBRARY_DIR};${OPENSSL_INCLUDE_DIR}/../bin;${ZLIB_INCLUDE_DIR}/../bin;/mingw32/bin")
endif()

if(BUILD_TESTING)
  add_subdirectory(${CMAKE_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR}/tests)
endif()
