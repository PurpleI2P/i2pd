cmake_minimum_required ( VERSION 2.8.12 )
# this addresses CMP0059 with CMake > 3.3 for PCH flags
cmake_policy( VERSION 2.8.12 )
project ( "i2pd" )

# for debugging
#set(CMAKE_VERBOSE_MAKEFILE on)

# configurale options
option(WITH_AESNI     "Use AES-NI instructions set" OFF)
option(WITH_HARDENING "Use hardening compiler flags" OFF)
option(WITH_LIBRARY   "Build library" ON)
option(WITH_BINARY    "Build binary" ON)
option(WITH_STATIC    "Static build" OFF)
option(WITH_UPNP "Include support for UPnP client" OFF)
option(WITH_PCH "Use precompiled header" OFF)
option(WITH_GUI "Include GUI (currently MS Windows only)" ON)
option(WITH_MESHNET "Build for cjdns test network" OFF)
option(WITH_ADDRSANITIZER "Build with address sanitizer unix only" OFF)
option(WITH_THREADSANITIZER "Build with thread sanitizer unix only" OFF)
option(WITH_I2LUA "Build for i2lua" OFF)
option(WITH_WEBSOCKETS "Build with websocket ui" OFF)

# paths
set ( CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules" )
set ( CMAKE_SOURCE_DIR ".." )

set (LIBI2PD_SRC
  "${CMAKE_SOURCE_DIR}/BloomFilter.cpp"
  "${CMAKE_SOURCE_DIR}/Config.cpp"
  "${CMAKE_SOURCE_DIR}/Crypto.cpp"
  "${CMAKE_SOURCE_DIR}/Garlic.cpp"
  "${CMAKE_SOURCE_DIR}/Gzip.cpp"
  "${CMAKE_SOURCE_DIR}/I2NPProtocol.cpp"
  "${CMAKE_SOURCE_DIR}/Identity.cpp"
  "${CMAKE_SOURCE_DIR}/LeaseSet.cpp"
  "${CMAKE_SOURCE_DIR}/FS.cpp"
  "${CMAKE_SOURCE_DIR}/Log.cpp"
  "${CMAKE_SOURCE_DIR}/NTCPSession.cpp"
  "${CMAKE_SOURCE_DIR}/NetDbRequests.cpp"
  "${CMAKE_SOURCE_DIR}/NetDb.cpp"
  "${CMAKE_SOURCE_DIR}/Profiling.cpp"
  "${CMAKE_SOURCE_DIR}/Reseed.cpp"
  "${CMAKE_SOURCE_DIR}/RouterContext.cpp"
  "${CMAKE_SOURCE_DIR}/RouterInfo.cpp"
  "${CMAKE_SOURCE_DIR}/SSU.cpp"
  "${CMAKE_SOURCE_DIR}/SSUData.cpp"
  "${CMAKE_SOURCE_DIR}/SSUSession.cpp"
  "${CMAKE_SOURCE_DIR}/Streaming.cpp"
  "${CMAKE_SOURCE_DIR}/Destination.cpp"
  "${CMAKE_SOURCE_DIR}/TransitTunnel.cpp"
  "${CMAKE_SOURCE_DIR}/Tunnel.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelGateway.cpp"
  "${CMAKE_SOURCE_DIR}/Transports.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelEndpoint.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelPool.cpp"
  "${CMAKE_SOURCE_DIR}/Base.cpp"
  "${CMAKE_SOURCE_DIR}/util.cpp"
  "${CMAKE_SOURCE_DIR}/Datagram.cpp"
  "${CMAKE_SOURCE_DIR}/Family.cpp"
  "${CMAKE_SOURCE_DIR}/Signature.cpp"
  "${CMAKE_SOURCE_DIR}/Timestamp.cpp"
  "${CMAKE_SOURCE_DIR}/api.cpp"
  "${CMAKE_SOURCE_DIR}/Event.cpp"
  "${CMAKE_SOURCE_DIR}/Gost.cpp"
)

if (WITH_WEBSOCKETS)
  add_definitions(-DWITH_EVENTS)
  find_package(websocketpp REQUIRED)
endif ()

if (CMAKE_SYSTEM_NAME STREQUAL "Windows" OR MSYS)
  list (APPEND LIBI2PD_SRC "${CMAKE_SOURCE_DIR}/I2PEndian.cpp")
endif ()

if (WITH_I2LUA)
  add_definitions(-DI2LUA)
endif()

add_library(libi2pd ${LIBI2PD_SRC})
set_target_properties(libi2pd PROPERTIES PREFIX "")
install(TARGETS libi2pd
  EXPORT libi2pd
  ARCHIVE DESTINATION lib
  COMPONENT Libraries)
# TODO Make libi2pd available to 3rd party projects via CMake as imported target
# FIXME This pulls stdafx
# install(EXPORT libi2pd DESTINATION ${CMAKE_INSTALL_LIBDIR})

set (CLIENT_SRC
  "${CMAKE_SOURCE_DIR}/AddressBook.cpp"
  "${CMAKE_SOURCE_DIR}/BOB.cpp"
  "${CMAKE_SOURCE_DIR}/ClientContext.cpp"
  "${CMAKE_SOURCE_DIR}/MatchedDestination.cpp"
  "${CMAKE_SOURCE_DIR}/I2PTunnel.cpp"
  "${CMAKE_SOURCE_DIR}/I2PService.cpp"
  "${CMAKE_SOURCE_DIR}/SAM.cpp"
  "${CMAKE_SOURCE_DIR}/SOCKS.cpp"
  "${CMAKE_SOURCE_DIR}/HTTP.cpp"
  "${CMAKE_SOURCE_DIR}/HTTPProxy.cpp"
  "${CMAKE_SOURCE_DIR}/I2CP.cpp"
  "${CMAKE_SOURCE_DIR}/WebSocks.cpp"
  )

if(WITH_WEBSOCKETS)
  list (APPEND CLIENT_SRC "${CMAKE_SOURCE_DIR}/Websocket.cpp")
endif ()
add_library(i2pdclient ${CLIENT_SRC})

set (DAEMON_SRC
  "${CMAKE_SOURCE_DIR}/Daemon.cpp"
  "${CMAKE_SOURCE_DIR}/HTTPServer.cpp"
  "${CMAKE_SOURCE_DIR}/I2PControl.cpp"
  "${CMAKE_SOURCE_DIR}/i2pd.cpp"
  "${CMAKE_SOURCE_DIR}/UPnP.cpp"
)

if (WITH_MESHNET)
  add_definitions(-DMESHNET)
endif ()

if (WITH_UPNP)
  add_definitions(-DUSE_UPNP)
  if (NOT MSVC AND NOT MSYS)
    set(DL_LIB ${CMAKE_DL_LIBS})
  endif ()
endif ()

# compiler flags customization (by vendor)
if (MSVC)
  add_definitions( -DWIN32_LEAN_AND_MEAN -DNOMINMAX )
  # TODO Check & report to Boost dev, there should be no need for these two
  add_definitions( -DBOOST_THREAD_NO_LIB -DBOOST_CHRONO_NO_LIB )
  set( CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL" )
  set( CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /INCREMENTAL:NO /LTCG" )
  set( CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELEASE} /GL" )
  set( CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} /INCREMENTAL:NO /LTCG" )
else()
  if (MSYS OR MINGW)
    add_definitions( -DWIN32_LEAN_AND_MEAN )
  endif ()
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
  set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11" )
elseif (CXX0X_SUPPORTED) # gcc 4.6
  set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x" )
elseif (NOT MSVC)
  message(SEND_ERROR "C++11 standart not seems to be supported by compiler. Too old version?")
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe")
  if (WITH_HARDENING)
    add_definitions( "-D_FORTIFY_SOURCE=2" )
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security -Werror=format-security" )
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector --param ssp-buffer-size=4" )
  endif ()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # more tweaks
endif ()

if (WITH_HARDENING AND MSVC)
  # Most security options like dynamic base, buffer & stack checks are ON by default
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /guard:cf" )
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
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/DaemonLinux.cpp")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows" OR MSYS)
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/DaemonWin32.cpp")
  if (WITH_GUI)
    list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/Win32/Win32App.cpp")
    set_source_files_properties("${CMAKE_SOURCE_DIR}/DaemonWin32.cpp"
      PROPERTIES COMPILE_DEFINITIONS WIN32_APP)
  endif ()
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/Win32/Win32Service.cpp")
  list (APPEND DAEMON_SRC "${CMAKE_SOURCE_DIR}/Win32/Resource.rc")
endif ()

if (WITH_AESNI)
  set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes" )
  add_definitions ( -DAESNI )
endif()

if (WITH_ADDRSANITIZER)
  if (NOT MSVC)
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer" )
    set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address" )
  else ()
    message( SEND_ERROR "MSVC does not support address sanitizer option")
  endif()
endif()

if (WITH_THREADSANITIZER)
  if (WITH_ADDRSANITIZER)
    message( FATAL_ERROR "thread sanitizer option cannot be combined with address sanitizer")
  elseif (NOT MSVC)
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread" )
    set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread" )
  else ()
    message( SEND_ERROR "MSVC does not support address sanitizer option")
  endif()
endif()


# libraries
# TODO: once CMake 3.1+ becomes mainstream, see e.g. http://stackoverflow.com/a/29871891/673826
# use imported Threads::Threads instead
set(THREADS_PREFER_PTHREAD_FLAG ON)
if (IOS)
  set(CMAKE_THREAD_LIBS_INIT "-lpthread")
  set(CMAKE_HAVE_THREADS_LIBRARY 1)
  set(CMAKE_USE_WIN32_THREADS_INIT 0)
  set(CMAKE_USE_PTHREADS_INIT 1)
else()
  find_package ( Threads REQUIRED )
endif()
if(THREADS_HAVE_PTHREAD_ARG) # compile time flag
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

if (WITH_STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
  if (WIN32 AND NOT MSYS AND NOT MINGW)
    # http://www.cmake.org/Wiki/CMake_FAQ#Dynamic_Replace
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
  if (NOT WIN32 AND NOT MSYS)
    # TODO: Consider separate compilation for LIBI2PD_SRC for library.
    # No need in -fPIC overhead for binary if not interested in library
    # HINT: revert c266cff CMakeLists.txt: compilation speed up
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC" )
  endif ()
  add_definitions(-DBOOST_SYSTEM_DYN_LINK -DBOOST_FILESYSTEM_DYN_LINK -DBOOST_PROGRAM_OPTIONS_DYN_LINK -DBOOST_DATE_TIME_DYN_LINK -DBOOST_REGEX_DYN_LINK)
endif ()

if (WITH_PCH)
  include_directories(BEFORE ${CMAKE_BINARY_DIR})
  add_library(stdafx STATIC "${CMAKE_SOURCE_DIR}/stdafx.cpp")
  if(MSVC)
    target_compile_options(stdafx PRIVATE /Ycstdafx.h /Zm155)
    add_custom_command(TARGET stdafx POST_BUILD
      COMMAND xcopy /y stdafx.dir\\$<CONFIG>\\*.pdb libi2pd.dir\\$<CONFIG>\\
      COMMAND xcopy /y stdafx.dir\\$<CONFIG>\\*.pdb i2pdclient.dir\\$<CONFIG>\\
      COMMAND xcopy /y stdafx.dir\\$<CONFIG>\\*.pdb i2pd.dir\\$<CONFIG>\\
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      )
    target_compile_options(libi2pd PRIVATE /FIstdafx.h /Yustdafx.h /Zm155 "/Fp${CMAKE_BINARY_DIR}/stdafx.dir/$<CONFIG>/stdafx.pch")
    target_compile_options(i2pdclient PRIVATE /FIstdafx.h /Yustdafx.h /Zm155 "/Fp${CMAKE_BINARY_DIR}/stdafx.dir/$<CONFIG>/stdafx.pch")
  else()
    string(TOUPPER ${CMAKE_BUILD_TYPE} BTU)
    get_directory_property(DEFS DEFINITIONS)
    string(REPLACE " " ";" FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BTU}} ${DEFS}")
    add_custom_command(TARGET stdafx PRE_BUILD
      COMMAND ${CMAKE_CXX_COMPILER} ${FLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/../stdafx.h -o ${CMAKE_BINARY_DIR}/stdafx.h.gch
    )
    target_compile_options(libi2pd PRIVATE -include stdafx.h)
    target_compile_options(i2pdclient PRIVATE -include stdafx.h)
  endif()
  target_link_libraries(libi2pd stdafx)
endif()

target_link_libraries(i2pdclient libi2pd)

find_package ( Boost COMPONENTS system filesystem program_options date_time REQUIRED )
if(NOT DEFINED Boost_INCLUDE_DIRS)
  message(SEND_ERROR "Boost is not found, or your boost version was bellow 1.46. Please download Boost!")
endif()

find_package ( OpenSSL REQUIRED )
if(NOT DEFINED OPENSSL_INCLUDE_DIR)
  message(SEND_ERROR "Could not find OpenSSL. Please download and install it first!")
endif()

if (WITH_UPNP)
  find_package ( MiniUPnPc REQUIRED )
  include_directories( SYSTEM ${MINIUPNPC_INCLUDE_DIR} )
endif()

find_package ( ZLIB )
if (NOT ZLIB_FOUND )
  # We are probably on Windows
  find_program( PATCH patch C:/Program Files/Git/usr/bin C:/msys64/usr/bin C:/msys32/usr/bin C:/Strawberry/c/bin )
  include( ExternalProject )
  if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
    set( ZLIB_EXTRA -DAMD64=ON )
  else()
    set( ZLIB_EXTRA -DASM686=ON "-DCMAKE_ASM_MASM_FLAGS=/W0 /safeseh" )
  endif()
  ExternalProject_Add(zlib-project
    URL http://zlib.net/zlib-1.2.8.tar.gz
    URL_MD5 44d667c142d7cda120332623eab69f40
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/zlib
    PATCH_COMMAND "${PATCH}" -p0 < ${CMAKE_CURRENT_SOURCE_DIR}/cmake-zlib-static.patch
      && "${PATCH}" -p0 < ${CMAKE_CURRENT_SOURCE_DIR}/cmake-zlib-amd64.patch
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
      -DWITH_STATIC=${WITH_STATIC} ${ZLIB_EXTRA}
    )
  if (WITH_PCH)
    add_dependencies( stdafx zlib-project )
  else ()
    add_dependencies( libi2pd zlib-project )
  endif ()
  # ExternalProject_Get_Property(zlib-project install_dir)
  set ( ZLIB_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/zlib/include" CACHE FILEPATH "zlib include dir" FORCE)
  if (NOT WITH_STATIC)
    set ( ZLIB_LIBRARY debug zlibd optimized zlib CACHE STRING "zlib libraries" FORCE)
  endif ()
endif ()
if (WITH_STATIC AND (MSVC OR MSYS))
  set ( ZLIB_LIBRARY debug zlibstaticd optimized zlibstatic CACHE STRING "zlib libraries" FORCE)
endif ()
link_directories(${CMAKE_CURRENT_BINARY_DIR}/zlib/lib ${ZLIB_ROOT}/lib)

# load includes
include_directories( SYSTEM ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR} )


# warn if for meshnet
if (WITH_MESHNET)
  message(STATUS "Building for testnet")
  message(WARNING "This build will NOT work on mainline i2p")
endif()


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
message(STATUS "  MESHNET          : ${WITH_MESHNET}")
message(STATUS "  ADDRSANITIZER    : ${WITH_ADDRSANITIZER}")
message(STATUS "  THEADSANITIZER   : ${WITH_THREADSANITIZER}")
message(STATUS "  I2LUA            : ${WITH_I2LUA}")
message(STATUS "  WEBSOCKETS       : ${WITH_WEBSOCKETS}")
message(STATUS "---------------------------------------")

#Handle paths nicely
include(GNUInstallDirs)

if (WITH_BINARY)
  add_executable ( "${PROJECT_NAME}" ${DAEMON_SRC} )
  if (WIN32 AND WITH_GUI)
    set_target_properties("${PROJECT_NAME}" PROPERTIES WIN32_EXECUTABLE TRUE )
  endif()
  if(NOT MSVC)
    if (WITH_STATIC)
      set_target_properties("${PROJECT_NAME}" PROPERTIES LINK_FLAGS "-static" )
    endif ()
  endif()

  if (WITH_PCH)
    if (MSVC)
      target_compile_options("${PROJECT_NAME}" PRIVATE /FIstdafx.h /Yustdafx.h /Zm155 "/Fp${CMAKE_BINARY_DIR}/stdafx.dir/$<CONFIG>/stdafx.pch")
    else()
      target_compile_options("${PROJECT_NAME}" PRIVATE -include stdafx.h)
    endif()
  endif()

  if (WITH_HARDENING AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NOT MSYS AND NOT MINGW)
    set_target_properties("${PROJECT_NAME}" PROPERTIES LINK_FLAGS "-z relro -z now" )
  endif ()

  if (WITH_UPNP)
	  target_link_libraries("${PROJECT_NAME}" "${MINIUPNPC_LIBRARY}")
  endif ()

  # FindBoost pulls pthread for thread which is broken for static linking at least on Ubuntu 15.04
  list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
  if(${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
    list(REMOVE_AT Boost_LIBRARIES -1)
  endif()

  if (MSYS OR MINGW)
    set (MINGW_EXTRA -lws2_32 -lmswsock -liphlpapi )
  endif ()
  if (WITH_STATIC)
    set(DL_LIB ${CMAKE_DL_LIBS})
  endif()
  target_link_libraries( "${PROJECT_NAME}" libi2pd i2pdclient ${DL_LIB} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${MINGW_EXTRA} ${DL_LIB})

  install(TARGETS "${PROJECT_NAME}" RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
  set (APPS "\${CMAKE_INSTALL_PREFIX}/bin/${PROJECT_NAME}${CMAKE_EXECUTABLE_SUFFIX}")
  set (DIRS "${Boost_LIBRARY_DIR};${OPENSSL_INCLUDE_DIR}/../bin;${ZLIB_INCLUDE_DIR}/../bin;/mingw32/bin")
  if (MSVC)
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION ${CMAKE_INSTALL_BINDIR} CONFIGURATIONS DEBUG RELWITHDEBINFO COMPONENT Symbols)
    # TODO Somehow this picks lots of unrelevant stuff with MSYS. OS X testing needed.
    INSTALL(CODE "
      include(BundleUtilities)
      fixup_bundle(\"${APPS}\"   \"\"   \"${DIRS}\")
      " COMPONENT Runtime)
  endif ()
endif ()

install(FILES ../LICENSE
  DESTINATION .
  COMPONENT Runtime
  )
# Take a copy on Appveyor
install(FILES "C:/projects/openssl-$ENV{OPENSSL}/LICENSE"
  DESTINATION .
  COMPONENT Runtime
  RENAME LICENSE_OPENSSL
  OPTIONAL                      # for local builds only!
  )

file(GLOB_RECURSE I2PD_SOURCES "../*.cpp" "../build" "../Win32" "../Makefile*")
install(FILES ${I2PD_SOURCES} DESTINATION src/ COMPONENT Source)
# install(DIRECTORY ../ DESTINATION src/
#   # OPTIONAL
#   COMPONENT Source FILES_MATCHING
#   PATTERN .git EXCLUDE
#   PATTERN "*.cpp"
#   )

file(GLOB I2PD_HEADERS "../*.h")
install(FILES ${I2PD_HEADERS} DESTINATION src/ COMPONENT Headers)
# install(DIRECTORY ../ DESTINATION src/
#   # OPTIONAL
#   COMPONENT Headers FILES_MATCHING
#   PATTERN .git EXCLUDE
#   PATTERN "*.h"
#   )

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Purple I2P, a C++ I2P daemon")
set(CPACK_PACKAGE_VENDOR "Purple I2P")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/../LICENSE")
file(READ ../version.h version_h)
string(REGEX REPLACE ".*I2PD_VERSION_MAJOR ([0-9]+).*" "\\1" CPACK_PACKAGE_VERSION_MAJOR "${version_h}")
string(REGEX REPLACE ".*I2PD_VERSION_MINOR ([0-9]+).*" "\\1" CPACK_PACKAGE_VERSION_MINOR "${version_h}")
string(REGEX REPLACE ".*I2PD_VERSION_MICRO ([0-9]+).*" "\\1" CPACK_PACKAGE_VERSION_MICRO "${version_h}")
string(REGEX REPLACE ".*I2PD_VERSION_PATCH ([0-9]+).*" "\\1" CPACK_PACKAGE_VERSION_PATCH "${version_h}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "Purple I2P")# ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}")
include(CPackComponent)
cpack_add_component(Runtime
  DESCRIPTION "Main files"
  REQUIRED INSTALL_TYPES minimal)
cpack_add_component(Symbols
  DISPLAY_NAME "Debug symbols"
  DESCRIPTION "Debug symbols for use with WinDbg or Visual Studio"
  INSTALL_TYPES recommended full
  )
cpack_add_component(Libraries
  DESCRIPTION "Binary libraries for development"
  INSTALL_TYPES full dev3rd
  )
cpack_add_component(Source
  DISPLAY_NAME "Source code"
  DESCRIPTION "I2pd source code"
  INSTALL_TYPES full
  )
cpack_add_component(Headers
  DISPLAY_NAME "Header files"
  DESCRIPTION "I2pd header files for development"
  INSTALL_TYPES full dev3rd
  )
install(FILES ${MINIUPNPC_INCLUDE_DIR}/miniupnpc/miniupnpc.dll
  DESTINATION bin
  COMPONENT MiniUPnPc
  OPTIONAL
  )
install(FILES ${MINIUPNPC_INCLUDE_DIR}/miniupnpc/LICENSE
  DESTINATION .
  COMPONENT MiniUPnPc
  RENAME LICENSE_MINIUPNPC
  OPTIONAL
  )
cpack_add_component(MiniUPnPc
  INSTALL_TYPES full recommended
  # DOWNLOADED
  # ARCHIVE_FILE miniupnpc-win32.zip
  )
cpack_add_install_type(recommended DISPLAY_NAME Recommended)
cpack_add_install_type(dev3rd DISPLAY_NAME "Third party development")
cpack_add_install_type(full DISPLAY_NAME Full)
cpack_add_install_type(minimal DISPLAY_NAME Minimal)
if((WIN32 OR MSYS) AND NOT UNIX)
  # There is a bug in NSI that does not handle full unix paths properly. Make
  # sure there is at least one set of four (4) backlasshes.
  set(CPACK_NSIS_DEFINES "RequestExecutionLevel user")
  set(CPACK_PACKAGE_ICON "${CMAKE_CURRENT_SOURCE_DIR}/../Win32\\\\mask.bmp")
  set(CPACK_NSIS_INSTALLED_ICON_NAME "bin/i2pd.exe")
  SET(CPACK_NSIS_DISPLAY_NAME "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
  set(CPACK_NSIS_HELP_LINK "https:\\\\\\\\github.com\\\\PurpleI2P\\\\i2pd\\\\issues")
  set(CPACK_NSIS_URL_INFO_ABOUT "https:\\\\\\\\github.com\\\\PurpleI2P\\\\i2pd")
  set(CPACK_NSIS_CREATE_ICONS_EXTRA "CreateShortCut '$SMPROGRAMS\\\\$STARTMENU_FOLDER\\\\Install i2pd as windows service.lnk' '$INSTDIR\\\\bin\\\\i2pd.exe' '--service=install'
CreateShortCut '$SMPROGRAMS\\\\$STARTMENU_FOLDER\\\\Remove i2pd windows service.lnk' '$INSTDIR\\\\bin\\\\i2pd.exe' '--service=remove'")
  set(CPACK_NSIS_DELETE_ICONS_EXTRA "Delete '$SMPROGRAMS\\\\$START_MENU\\\\Install i2pd as windows service.lnk'
Delete '$SMPROGRAMS\\\\$START_MENU\\\\Remove i2pd windows service.lnk'")
else()
  set(CPACK_STRIP_FILES "bin/i2pd")
  set(CPACK_SOURCE_STRIP_FILES "")
endif()
set(CPACK_PACKAGE_EXECUTABLES "i2pd" "C++ I2P daemon")
set(CPACK_SOURCE_GENERATOR "TGZ")
include(CPack)
