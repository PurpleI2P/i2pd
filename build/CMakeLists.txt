cmake_minimum_required(VERSION 2.8.12)
# this addresses CMP0059 with CMake > 3.3 for PCH flags
cmake_policy(VERSION 2.8.12)
project("i2pd")

# for debugging
#set(CMAKE_VERBOSE_MAKEFILE on)

# Win32 build with cmake is not supported
if(WIN32 OR MSVC OR MSYS OR MINGW)
  message(SEND_ERROR "cmake build for windows is not supported. Please use MSYS2 with makefiles in project root.")
endif()

# configurable options
option(WITH_AESNI           "Use AES-NI instructions set"             ON)
option(WITH_HARDENING       "Use hardening compiler flags"            OFF)
option(WITH_LIBRARY         "Build library"                           ON)
option(WITH_BINARY          "Build binary"                            ON)
option(WITH_STATIC          "Static build"                            OFF)
option(WITH_UPNP            "Include support for UPnP client"         OFF)
option(WITH_PCH             "Use precompiled header"                  OFF)
option(WITH_MESHNET         "Build for cjdns test network"            OFF)
option(WITH_ADDRSANITIZER   "Build with address sanitizer unix only"  OFF)
option(WITH_THREADSANITIZER "Build with thread sanitizer unix only"   OFF)

# paths
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules")
set(CMAKE_SOURCE_DIR "..")

# architecture
include(TargetArch)
target_architecture(ARCHITECTURE)

set(LIBI2PD_SRC_DIR ../libi2pd)
set(LIBI2PD_CLIENT_SRC_DIR ../libi2pd_client)
set(DAEMON_SRC_DIR ../daemon)

include_directories(${LIBI2PD_SRC_DIR})
include_directories(${LIBI2PD_CLIENT_SRC_DIR})
include_directories(${DAEMON_SRC_DIR})

set(LIBI2PD_SRC
  "${LIBI2PD_SRC_DIR}/api.cpp"
  "${LIBI2PD_SRC_DIR}/Base.cpp"
  "${LIBI2PD_SRC_DIR}/Blinding.cpp"
  "${LIBI2PD_SRC_DIR}/BloomFilter.cpp"
  "${LIBI2PD_SRC_DIR}/ChaCha20.cpp"
  "${LIBI2PD_SRC_DIR}/Config.cpp"
  "${LIBI2PD_SRC_DIR}/CPU.cpp"
  "${LIBI2PD_SRC_DIR}/Crypto.cpp"
  "${LIBI2PD_SRC_DIR}/CryptoKey.cpp"
  "${LIBI2PD_SRC_DIR}/Datagram.cpp"
  "${LIBI2PD_SRC_DIR}/Destination.cpp"
  "${LIBI2PD_SRC_DIR}/ECIESX25519AEADRatchetSession.cpp"
  "${LIBI2PD_SRC_DIR}/Ed25519.cpp"
  "${LIBI2PD_SRC_DIR}/Elligator.cpp"
  "${LIBI2PD_SRC_DIR}/Family.cpp"
  "${LIBI2PD_SRC_DIR}/FS.cpp"
  "${LIBI2PD_SRC_DIR}/Garlic.cpp"
  "${LIBI2PD_SRC_DIR}/Gost.cpp"
  "${LIBI2PD_SRC_DIR}/Gzip.cpp"
  "${LIBI2PD_SRC_DIR}/HTTP.cpp"
  "${LIBI2PD_SRC_DIR}/I2NPProtocol.cpp"
  "${LIBI2PD_SRC_DIR}/Identity.cpp"
  "${LIBI2PD_SRC_DIR}/LeaseSet.cpp"
  "${LIBI2PD_SRC_DIR}/Log.cpp"
  "${LIBI2PD_SRC_DIR}/NetDb.cpp"
  "${LIBI2PD_SRC_DIR}/NetDbRequests.cpp"
  "${LIBI2PD_SRC_DIR}/NTCP2.cpp"
  "${LIBI2PD_SRC_DIR}/Poly1305.cpp"
  "${LIBI2PD_SRC_DIR}/Profiling.cpp"
  "${LIBI2PD_SRC_DIR}/Reseed.cpp"
  "${LIBI2PD_SRC_DIR}/RouterContext.cpp"
  "${LIBI2PD_SRC_DIR}/RouterInfo.cpp"
  "${LIBI2PD_SRC_DIR}/Signature.cpp"
  "${LIBI2PD_SRC_DIR}/SSU.cpp"
  "${LIBI2PD_SRC_DIR}/SSUData.cpp"
  "${LIBI2PD_SRC_DIR}/SSUSession.cpp"
  "${LIBI2PD_SRC_DIR}/Streaming.cpp"
  "${LIBI2PD_SRC_DIR}/Timestamp.cpp"
  "${LIBI2PD_SRC_DIR}/TransitTunnel.cpp"
  "${LIBI2PD_SRC_DIR}/Transports.cpp"
  "${LIBI2PD_SRC_DIR}/Tunnel.cpp"
  "${LIBI2PD_SRC_DIR}/TunnelEndpoint.cpp"
  "${LIBI2PD_SRC_DIR}/TunnelGateway.cpp"
  "${LIBI2PD_SRC_DIR}/TunnelPool.cpp"
  "${LIBI2PD_SRC_DIR}/TunnelConfig.cpp"
  "${LIBI2PD_SRC_DIR}/util.cpp"
)

add_library(libi2pd ${LIBI2PD_SRC})
set_target_properties(libi2pd PROPERTIES PREFIX "")

if(WITH_LIBRARY)
  install(TARGETS libi2pd
    EXPORT libi2pd
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    COMPONENT Libraries)
# TODO Make libi2pd available to 3rd party projects via CMake as imported target
# FIXME This pulls stdafx
# install(EXPORT libi2pd DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

set(CLIENT_SRC
  "${LIBI2PD_CLIENT_SRC_DIR}/AddressBook.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/BOB.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/ClientContext.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/MatchedDestination.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/I2PTunnel.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/I2PService.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/SAM.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/SOCKS.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/HTTPProxy.cpp"
  "${LIBI2PD_CLIENT_SRC_DIR}/I2CP.cpp"
)

add_library(libi2pdclient ${CLIENT_SRC})
set_target_properties(libi2pdclient PROPERTIES PREFIX "")

if(WITH_LIBRARY)
  install(TARGETS libi2pdclient
    EXPORT libi2pdclient
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    COMPONENT Libraries)
endif()

set(DAEMON_SRC
  "${DAEMON_SRC_DIR}/Daemon.cpp"
  "${DAEMON_SRC_DIR}/HTTPServer.cpp"
  "${DAEMON_SRC_DIR}/I2PControl.cpp"
  "${DAEMON_SRC_DIR}/i2pd.cpp"
  "${DAEMON_SRC_DIR}/UPnP.cpp"
)

if(WITH_MESHNET)
  add_definitions(-DMESHNET)
endif()

if(WITH_UPNP)
  add_definitions(-DUSE_UPNP)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")
# TODO: The following is incompatible with static build and enabled hardening for OpenWRT.
# Multiple definitions of __stack_chk_fail(libssp & libc)
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections")
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections") # -flto is added from above

# check for c++17 & c++11 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" CXX17_SUPPORTED)
CHECK_CXX_COMPILER_FLAG("-std=c++11" CXX11_SUPPORTED)
if(CXX17_SUPPORTED)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
elseif(CXX11_SUPPORTED)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
  message(SEND_ERROR "C++17 nor C++11 standard not seems to be supported by compiler. Too old version?")
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
if(WITH_AESNI AND (ARCHITECTURE MATCHES "x86_64" OR ARCHITECTURE MATCHES "i386"))
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
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


# libraries
# TODO: once CMake 3.1+ becomes mainstream, see e.g. http://stackoverflow.com/a/29871891/673826
# use imported Threads::Threads instead
set(THREADS_PREFER_PTHREAD_FLAG ON)
if(IOS)
  set(CMAKE_THREAD_LIBS_INIT "-lpthread")
  set(CMAKE_HAVE_THREADS_LIBRARY 1)
  set(CMAKE_USE_WIN32_THREADS_INIT 0)
  set(CMAKE_USE_PTHREADS_INIT 1)
else()
  find_package(Threads REQUIRED)
endif()
if(THREADS_HAVE_PTHREAD_ARG) # compile time flag
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

if(WITH_STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
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
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
  add_definitions(-DBOOST_SYSTEM_DYN_LINK -DBOOST_FILESYSTEM_DYN_LINK -DBOOST_PROGRAM_OPTIONS_DYN_LINK -DBOOST_DATE_TIME_DYN_LINK -DBOOST_REGEX_DYN_LINK)
endif()

if(WITH_PCH)
  include_directories(BEFORE ${CMAKE_BINARY_DIR})
  add_library(stdafx STATIC "${LIBI2PD_SRC_DIR}/stdafx.cpp")
  string(TOUPPER ${CMAKE_BUILD_TYPE} BTU)
  get_directory_property(DEFS DEFINITIONS)
  string(REPLACE " " ";" FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BTU}} ${DEFS}")
  add_custom_command(TARGET stdafx PRE_BUILD
    COMMAND ${CMAKE_CXX_COMPILER} ${FLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/../libi2pd/stdafx.h -o ${CMAKE_BINARY_DIR}/stdafx.h.gch
  )
  target_compile_options(libi2pd PRIVATE -include libi2pd/stdafx.h)
  target_compile_options(libi2pdclient PRIVATE -include libi2pd/stdafx.h)
  target_link_libraries(libi2pd stdafx)
endif()

target_link_libraries(libi2pdclient libi2pd)

find_package(Boost COMPONENTS system filesystem program_options date_time REQUIRED)
if(NOT DEFINED Boost_INCLUDE_DIRS)
  message(SEND_ERROR "Boost is not found, or your boost version was below 1.46. Please download Boost!")
endif()

find_package(OpenSSL REQUIRED)
if(NOT DEFINED OPENSSL_INCLUDE_DIR)
  message(SEND_ERROR "Could not find OpenSSL. Please download and install it first!")
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

# load includes
include_directories(SYSTEM ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})

# warn if for meshnet
if(WITH_MESHNET)
  message(STATUS "Building for testnet")
  message(WARNING "This build will NOT work on mainline i2p")
endif()

if(NOT MSYS)
  include(CheckAtomic)
endif()

# show summary
message(STATUS "---------------------------------------")
message(STATUS "Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler vendor    : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version   : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiler path      : ${CMAKE_CXX_COMPILER}")
message(STATUS "Architecture       : ${ARCHITECTURE}")
message(STATUS "Install prefix:    : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Options:")
message(STATUS "  AESNI            : ${WITH_AESNI}")
message(STATUS "  HARDENING        : ${WITH_HARDENING}")
message(STATUS "  LIBRARY          : ${WITH_LIBRARY}")
message(STATUS "  BINARY           : ${WITH_BINARY}")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "  UPnP             : ${WITH_UPNP}")
message(STATUS "  PCH              : ${WITH_PCH}")
message(STATUS "  MESHNET          : ${WITH_MESHNET}")
message(STATUS "  ADDRSANITIZER    : ${WITH_ADDRSANITIZER}")
message(STATUS "  THREADSANITIZER  : ${WITH_THREADSANITIZER}")
message(STATUS "---------------------------------------")

#Handle paths nicely
include(GNUInstallDirs)

if(WITH_BINARY)
  add_executable("${PROJECT_NAME}" ${DAEMON_SRC})

  if(WITH_STATIC)
    set_target_properties("${PROJECT_NAME}" PROPERTIES LINK_FLAGS "-static")
  endif()

  if(WITH_PCH)
    target_compile_options("${PROJECT_NAME}" PRIVATE -include libi2pd/stdafx.h)
  endif()

  if(WITH_HARDENING AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties("${PROJECT_NAME}" PROPERTIES LINK_FLAGS "-z relro -z now")
  endif()

  if(WITH_UPNP)
    set(UPNP_LIB ${MINIUPNPC_LIBRARY})
  endif()

  # FindBoost pulls pthread for thread which is broken for static linking at least on Ubuntu 15.04
  list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
  if(${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
    list(REMOVE_AT Boost_LIBRARIES -1)
  endif()


  if(WITH_STATIC)
    set(DL_LIB ${CMAKE_DL_LIBS})
  endif()

  target_link_libraries(libi2pd ${Boost_LIBRARIES} ${ZLIB_LIBRARY})
  target_link_libraries("${PROJECT_NAME}" libi2pd libi2pdclient ${DL_LIB} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${UPNP_LIB} ${ZLIB_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${MINGW_EXTRA} ${DL_LIB} ${CMAKE_REQUIRED_LIBRARIES})

  install(TARGETS "${PROJECT_NAME}" RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
  set(APPS "\${CMAKE_INSTALL_PREFIX}/bin/${PROJECT_NAME}${CMAKE_EXECUTABLE_SUFFIX}")
  set(DIRS "${Boost_LIBRARY_DIR};${OPENSSL_INCLUDE_DIR}/../bin;${ZLIB_INCLUDE_DIR}/../bin;/mingw32/bin")
endif()
