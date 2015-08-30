cmake_minimum_required ( VERSION 2.8.12 )
project ( "i2pd" )

# configurale options
option(WITH_AESNI     "Use AES-NI instructions set" OFF)
option(WITH_HARDENING "Use hardening compiler flags" OFF)
option(WITH_LIBRARY   "Build library" ON)
option(WITH_BINARY    "Build binary" ON)
option(WITH_STATIC    "Static build" OFF)
option(WITH_UPNP      "Include support for UPnP client" OFF)
option(WITH_TESTS     "Build unit tests" OFF)
option(WITH_BENCHMARK "Build benchmarking code" OFF)
option(WITH_OPTIMIZE  "Optmizeation flags" OFF)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/build/cmake_modules")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Default build is Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# compiler flags customization (by vendor)
if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")
    # TODO: The following is incompatible with static build and enabled hardening
    #  for OpenWRT.
    # Multiple definitions of __stack_chk_fail (libssp & libc)
    set(
        CMAKE_CXX_FLAGS_MINSIZEREL
        "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections"
    )
    # -flto is added from above
    set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections")
endif()

# Check for c++11 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" CXX11_SUPPORTED)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" CXX0X_SUPPORTED)
if(CXX11_SUPPORTED)
    add_definitions("-std=c++11")
elseif(CXX0X_SUPPORTED) # gcc 4.6
    add_definitions("-std=c++0x")
elseif(NOT MSVC)
    message(SEND_ERROR "C++11 standard not supported by compiler. Version too old?")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(WITH_HARDENING)
        add_definitions( "-D_FORTIFY_SOURCE=2" )
        set(
            CMAKE_CXX_FLAGS
            "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security -Werror=format-security"
        )
        set(
            CMAKE_CXX_FLAGS
            "${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIE --param ssp-buffer-size=4 -z relro -z now"
        )
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # TODO: Clang-specific flags 
endif()

# Compiler flags customization (by system)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  # "'sleep_for' is not a member of 'std::this_thread'" in gcc 4.7/4.8
  add_definitions( "-D_GLIBCXX_USE_NANOSLEEP=1" )
endif ()

if(WITH_UPNP)
    add_definitions(-DUSE_UPNP)
    if(NOT MSVC)
        set(DL_LIB ${CMAKE_DL_LIBS})
    endif()
endif()

if(WITH_AESNI)
    add_definitions( "-maes -DAESNI")
endif()

if(WITH_OPTIMIZE AND (NOT MSVC))
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif()

# Libraries
# TODO: once CMake 3.1+ becomes mainstream, see e.g.
#  http://stackoverflow.com/a/29871891/673826 use imported Threads::Threads
#  instead
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package (Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG) # compile time flag
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

if(WITH_STATIC)
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_STATIC_RUNTIME ON)
    if(WIN32)
        # http://www.cmake.org/Wiki/CMake_FAQ#Dynamic_Replace
        # Note that you might need to rebuild Crypto++
        foreach(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
         CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
            if(${flag_var} MATCHES "/MD")
                string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
            endif(${flag_var} MATCHES "/MD")
        endforeach(flag_var)
    else()
        set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    endif()

    set(BUILD_SHARED_LIBS OFF)
    if(${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
        set(
            CMAKE_THREAD_LIBS_INIT
            "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,-u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal,-u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,-u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel"
        )
    endif()
elseif(NOT WIN32)
    # TODO: Consider separate compilation for COMMON_SRC for library.
    # No need in -fPIC overhead for binary if not interested in library
    # HINT: revert c266cff CMakeLists.txt: compilation speed up
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif()

add_definitions(-DBOOST_ALL_DYN_LINK)

find_package(
    Boost COMPONENTS
    system filesystem regex program_options date_time thread chrono REQUIRED
)
if(NOT DEFINED Boost_INCLUDE_DIRS)
    message(SEND_ERROR "Boost not found, or version below 1.46. Please download Boost!")
endif()

find_package(CryptoPP REQUIRED)
if(NOT DEFINED CRYPTO++_INCLUDE_DIR)
  message(SEND_ERROR "Could not find Crypto++. Please download and install it first!")
endif()

find_package(MiniUPnPc)
if(NOT ${MINIUPNPC_FOUND})
    set(WITH_UPNP OFF)
endif()

# Load includes
include_directories(
    ${CMAKE_SOURCE_DIR} ${Boost_INCLUDE_DIRS} ${CRYPTO++_INCLUDE_DIR}
    "core/"
)

# Show summary
message(STATUS "---------------------------------------")
message(STATUS "Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler vendor    : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version   : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiler path      : ${CMAKE_CXX_COMPILER}")
message(STATUS "Install prefix:    : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Options:")
message(STATUS "  AESNI            : ${WITH_AESNI}")
message(STATUS "  HARDENING        : ${WITH_HARDENING}")
message(STATUS "  LIBRARY          : ${WITH_LIBRARY}")
message(STATUS "  BINARY           : ${WITH_BINARY}")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "  UPnP             : ${WITH_UPNP}")
message(STATUS "  TESTS            : ${WITH_TESTS}")
message(STATUS "  BENCHMARKING     : ${WITH_BENCHMARK}")
message(STATUS "  OPTIMIZATION     : ${WITH_OPTIMIZE}")
message(STATUS "---------------------------------------")

# Handle paths nicely
include(GNUInstallDirs)

set(CORE_NAME "${PROJECT_NAME}-core")
set(CLIENT_NAME "${PROJECT_NAME}-client")
set(TESTS_NAME "${PROJECT_NAME}-tests")
set(BENCHMARK_NAME "${PROJECT_NAME}-benchmark")
add_subdirectory(core)
add_subdirectory(client)
add_subdirectory(tests)
add_subdirectory(benchmark)
