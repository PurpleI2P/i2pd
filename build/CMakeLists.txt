cmake_minimum_required ( VERSION 2.8.12 )
project ( "i2pd" )

# configurale options
option(WITH_AESNI     "Use AES-NI instructions set" OFF)
option(WITH_HARDENING "Use hardening compiler flags" OFF)
option(WITH_LIBRARY   "Build library" ON)
option(WITH_BINARY    "Build binary" ON)
option(WITH_STATIC    "Static build" OFF)
option(WITH_UPNP "Include support for UPnP client" OFF)
option(WITH_PCH "Use precompiled header" OFF)

# paths
set ( CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules" )
set ( CMAKE_SOURCE_DIR ".." )

set (COMMON_SRC
  "${CMAKE_SOURCE_DIR}/transport/NTCPSession.cpp"
  "${CMAKE_SOURCE_DIR}/transport/SSU.cpp"
  "${CMAKE_SOURCE_DIR}/transport/SSUData.cpp"
  "${CMAKE_SOURCE_DIR}/transport/SSUSession.cpp"
  "${CMAKE_SOURCE_DIR}/transport/Transports.cpp"
  "${CMAKE_SOURCE_DIR}/crypto/CryptoConst.cpp"
  "${CMAKE_SOURCE_DIR}/crypto/aes.cpp"
  "${CMAKE_SOURCE_DIR}/crypto/Signature.cpp"
  "${CMAKE_SOURCE_DIR}/util/base64.cpp"
  "${CMAKE_SOURCE_DIR}/util/util.cpp"
  "${CMAKE_SOURCE_DIR}/util/Log.cpp"
  "${CMAKE_SOURCE_DIR}/AddressBook.cpp"	
  "${CMAKE_SOURCE_DIR}/Garlic.cpp"
  "${CMAKE_SOURCE_DIR}/I2NPProtocol.cpp"
  "${CMAKE_SOURCE_DIR}/Identity.cpp"
  "${CMAKE_SOURCE_DIR}/LeaseSet.cpp"
  "${CMAKE_SOURCE_DIR}/NetDbRequests.cpp"	
  "${CMAKE_SOURCE_DIR}/NetDb.cpp"
  "${CMAKE_SOURCE_DIR}/Profiling.cpp"
  "${CMAKE_SOURCE_DIR}/Reseed.cpp"
  "${CMAKE_SOURCE_DIR}/RouterContext.cpp"
  "${CMAKE_SOURCE_DIR}/RouterInfo.cpp"
  "${CMAKE_SOURCE_DIR}/Streaming.cpp"
  "${CMAKE_SOURCE_DIR}/Destination.cpp"	
  "${CMAKE_SOURCE_DIR}/TransitTunnel.cpp"
  "${CMAKE_SOURCE_DIR}/Tunnel.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelGateway.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelEndpoint.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelPool.cpp"
  "${CMAKE_SOURCE_DIR}/Datagram.cpp"
  "${CMAKE_SOURCE_DIR}/UPnP.cpp"
)

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list (APPEND COMMON_SRC "${CMAKE_SOURCE_DIR}/util/I2PEndian.cpp")
endif ()

add_library(common ${COMMON_SRC})

set (DAEMON_SRC
  "${CMAKE_SOURCE_DIR}/BOB.cpp"	
  "${CMAKE_SOURCE_DIR}/ClientContext.cpp"
  "${CMAKE_SOURCE_DIR}/Daemon.cpp"
  "${CMAKE_SOURCE_DIR}/HTTPProxy.cpp"
  "${CMAKE_SOURCE_DIR}/HTTPServer.cpp"
  "${CMAKE_SOURCE_DIR}/I2PService.cpp"
  "${CMAKE_SOURCE_DIR}/I2PControl.cpp"	
  "${CMAKE_SOURCE_DIR}/I2PTunnel.cpp"
  "${CMAKE_SOURCE_DIR}/SAM.cpp"
  "${CMAKE_SOURCE_DIR}/SOCKS.cpp"
  "${CMAKE_SOURCE_DIR}/i2p.cpp"
)

if (WITH_UPNP)
  add_definitions(-DUSE_UPNP)
  if (NOT MSVC)
    set(DL_LIB ${CMAKE_DL_LIBS})
  endif ()
endif ()

set (LIBRARY_SRC
  "${CMAKE_SOURCE_DIR}/api.cpp"
)

file (GLOB HEADERS "${CMAKE_SOURCE_DIR}/*.h")

# MSVS grouping
source_group ("Header Files" FILES ${HEADERS})
source_group ("Source Files" FILES ${COMMON_SRC} ${DAEMON_SRC} ${LIBRARY_SRC})

# Default build is Debug
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif ()

# compiler flags customization (by vendor)
if (NOT MSVC)
  set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch" )
  set( CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic" )
  # TODO: The following is incompatible with static build and enabled hardening for OpenWRT.
  # Multiple definitions of __stack_chk_fail (libssp & libc)
  set( CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections" )
  set( CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections" ) # -flto is added from above
endif ()

# check for c++11 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" CXX11_SUPPORTED)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" CXX0X_SUPPORTED)
if (CXX11_SUPPORTED)
  add_definitions( "-std=c++11" )
elseif (CXX0X_SUPPORTED) # gcc 4.6
  add_definitions( "-std=c++0x" )
elseif (NOT MSVC)
  message(SEND_ERROR "C++11 standart not seems to be supported by compiler. Too old version?")
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if (WITH_HARDENING)
    add_definitions( "-D_FORTIFY_SOURCE=2" )
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security -Werror=format-security" )
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector --param ssp-buffer-size=4" )
  endif ()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # more tweaks
endif ()

# compiler flags customization (by system)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/DaemonLinux.cpp")
  # "'sleep_for' is not a member of 'std::this_thread'" in gcc 4.7/4.8
  add_definitions( "-D_GLIBCXX_USE_NANOSLEEP=1" )
elseif (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/DaemonLinux.cpp")
  # "'sleep_for' is not a member of 'std::this_thread'" in gcc 4.7/4.8
  add_definitions( "-D_GLIBCXX_USE_NANOSLEEP=1" )
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/DaemonLinux.cpp")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/DaemonWin32.cpp")
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/Win32/Win32Service.cpp")
endif ()

if (WITH_AESNI)
  add_definitions ( "-maes -DAESNI" )
endif()

# libraries
# TODO: once CMake 3.1+ becomes mainstream, see e.g. http://stackoverflow.com/a/29871891/673826
# use imported Threads::Threads instead
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package ( Threads REQUIRED )
if(THREADS_HAVE_PTHREAD_ARG) # compile time flag
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

if (WITH_STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
  if (WIN32)
    # http://www.cmake.org/Wiki/CMake_FAQ#Dynamic_Replace
    # Note that you might need to rebuild Crypto++
    foreach(flag_var
            CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
            CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
      if(${flag_var} MATCHES "/MD")
        string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
      endif(${flag_var} MATCHES "/MD")
    endforeach(flag_var)
  else ()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  endif ()
  set(BUILD_SHARED_LIBS OFF)
  if (${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread" )
    # set( CMAKE_THREAD_LIBS_INIT "gcc_eh -Wl,--whole-archive -lpthread -Wl,--no-whole-archive" )
    set( CMAKE_THREAD_LIBS_INIT "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,-u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal,-u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,-u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel" )
  endif ()
else()
  if (NOT WIN32)
    # TODO: Consider separate compilation for COMMON_SRC for library.
    # No need in -fPIC overhead for binary if not interested in library
    # HINT: revert c266cff CMakeLists.txt: compilation speed up
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC" )
  endif ()
  add_definitions(-DBOOST_ALL_DYN_LINK)
endif ()

if (WITH_PCH)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)
  add_library(stdafx STATIC "${CMAKE_SOURCE_DIR}/stdafx.cpp")
  if(MSVC)
    target_compile_options(stdafx PRIVATE /Ycstdafx.h /Zm135)
    add_custom_command(TARGET stdafx POST_BUILD
      COMMAND xcopy /y stdafx.dir\\$<CONFIG>\\*.pdb common.dir\\$<CONFIG>\\
      COMMAND xcopy /y stdafx.dir\\$<CONFIG>\\*.pdb i2pd-bin.dir\\$<CONFIG>\\
      COMMAND xcopy /y stdafx.dir\\$<CONFIG>\\*.pdb i2pd.dir\\$<CONFIG>\\
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      )
    target_compile_options(common PRIVATE /FIstdafx.h /Yustdafx.h /Zm135 "/Fp${CMAKE_BINARY_DIR}/stdafx.dir/$<CONFIG>/stdafx.pch")
  else()
    string(TOUPPER ${CMAKE_BUILD_TYPE} BTU)
    get_directory_property(DEFS DEFINITIONS)
    string(REPLACE " " ";" FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BTU}} ${DEFS}")
    add_custom_command(TARGET stdafx PRE_BUILD
      COMMAND ${CMAKE_CXX_COMPILER} ${FLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/../stdafx.h
    )
    target_compile_options(common PRIVATE -include stdafx.h)
  endif()
  target_link_libraries(common stdafx)
endif()

find_package ( Boost COMPONENTS system filesystem regex program_options date_time thread chrono REQUIRED )
if(NOT DEFINED Boost_INCLUDE_DIRS)
  message(SEND_ERROR "Boost is not found, or your boost version was bellow 1.46. Please download Boost!")
endif()

find_package ( CryptoPP REQUIRED )
if(NOT DEFINED CRYPTO++_INCLUDE_DIR)
  message(SEND_ERROR "Could not find Crypto++. Please download and install it first!")
endif()

find_package ( MiniUPnPc )
if (NOT ${MINIUPNPC_FOUND})
  set(WITH_UPNP OFF)
endif()

# load includes
include_directories( ${CMAKE_SOURCE_DIR}  ${Boost_INCLUDE_DIRS} ${CRYPTO++_INCLUDE_DIR} )

# show summary
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
message(STATUS "  PCH              : ${WITH_PCH}")
message(STATUS "---------------------------------------")

#Handle paths nicely
include(GNUInstallDirs)

if (WITH_BINARY)
  add_executable ( "${PROJECT_NAME}-bin" ${DAEMON_SRC} )
 if(NOT MSVC) # FIXME: incremental linker file name (.ilk) collision for dll & exe
  set_target_properties("${PROJECT_NAME}-bin" PROPERTIES OUTPUT_NAME "${PROJECT_NAME}")
  if (WITH_STATIC)
    set_target_properties("${PROJECT_NAME}-bin" PROPERTIES LINK_FLAGS "-static" )
  endif ()
 endif()

  if (WITH_PCH)
    if (MSVC)
      target_compile_options("${PROJECT_NAME}-bin" PRIVATE /FIstdafx.h /Yustdafx.h /Zm135 "/Fp${CMAKE_BINARY_DIR}/stdafx.dir/$<CONFIG>/stdafx.pch")
    else()
      target_compile_options("${PROJECT_NAME}-bin" PRIVATE -include stdafx.h)
    endif()
  endif()

  if (WITH_HARDENING AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties("${PROJECT_NAME}-bin" PROPERTIES LINK_FLAGS "-z relro -z now" )
  endif ()

  # FindBoost pulls pthread for thread which is broken for static linking at least on Ubuntu 15.04
  list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
  if(${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
    list(REMOVE_AT Boost_LIBRARIES -1)
  endif()
  target_link_libraries( "${PROJECT_NAME}-bin" common ${DL_LIB} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )

  install(TARGETS "${PROJECT_NAME}-bin" RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} )
  if (MSVC)
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}-bin> DESTINATION "bin" CONFIGURATIONS DEBUG)
  endif ()
endif ()

if (WITH_LIBRARY)
 if (MSVC)
  # FIXME: DLL would not have any symbols unless we use __declspec(dllexport) through out the code
  add_library(${PROJECT_NAME} STATIC ${LIBRARY_SRC})
 else ()
  add_library(${PROJECT_NAME} ${LIBRARY_SRC})
  target_link_libraries( ${PROJECT_NAME} common ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES})
 endif ()
  if (WITH_PCH)
    if (MSVC)
      add_dependencies(${PROJECT_NAME} stdafx)
      target_compile_options(${PROJECT_NAME} PRIVATE /FIstdafx.h /Yustdafx.h /Zm135 "/Fp${CMAKE_BINARY_DIR}/stdafx.dir/$<CONFIG>/stdafx.pch")
    else()
      target_compile_options(${PROJECT_NAME} PRIVATE -include stdafx.h)
    endif()
  endif()
  install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()
