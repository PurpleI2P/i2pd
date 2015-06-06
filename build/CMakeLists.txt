cmake_minimum_required ( VERSION 2.8.5 )
project ( "i2pd" )

# configurale options
option(WITH_AESNI     "Use AES-NI instructions set" OFF)
option(WITH_HARDENING "Use hardening compiler flags" OFF)
option(WITH_LIBRARY   "Build library" ON)
option(WITH_BINARY    "Build binary" ON)
option(WITH_STATIC    "Static build" OFF)
option(WITH_UPNP "Include support for UPnP client" OFF)

# paths
set ( CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules" )
set ( CMAKE_SOURCE_DIR ".." )

set (COMMON_SRC
  "${CMAKE_SOURCE_DIR}/AddressBook.cpp"	
  "${CMAKE_SOURCE_DIR}/CryptoConst.cpp"
  "${CMAKE_SOURCE_DIR}/Garlic.cpp"
  "${CMAKE_SOURCE_DIR}/I2NPProtocol.cpp"
  "${CMAKE_SOURCE_DIR}/Identity.cpp"
  "${CMAKE_SOURCE_DIR}/LeaseSet.cpp"
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
  "${CMAKE_SOURCE_DIR}/aes.cpp"
  "${CMAKE_SOURCE_DIR}/base64.cpp"
  "${CMAKE_SOURCE_DIR}/util.cpp"
  "${CMAKE_SOURCE_DIR}/Datagram.cpp"
  "${CMAKE_SOURCE_DIR}/Signature.cpp"
  "${CMAKE_SOURCE_DIR}/UPnP.cpp"
)

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list (APPEND COMMON_SRC "${CMAKE_SOURCE_DIR}/I2PEndian.cpp")
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
endif ()

set (LIBRARY_SRC
  "${CMAKE_SOURCE_DIR}/api.cpp"
)

file (GLOB HEADERS "${CMAKE_SOURCE_DIR}/*.h")

# MSVS grouping
source_group ("Header Files" FILES ${HEADERS})
source_group ("Source Files" FILES ${COMMON_SRC} ${DAEMON_SRC} ${LIBRARY_SRC})

# Default build is Debug
if (CMAKE_BUILD_TYPE STREQUAL "Release")
  add_definitions( "-pedantic" )
else ()
  set(CMAKE_BUILD_TYPE Debug)
endif ()

# compiler flags customization (by vendor)
if (NOT MSVC)
add_definitions ( "-Wall -Wextra -fPIC" )
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
find_package ( Threads REQUIRED )

if (WITH_STATIC)
  set(Boost_USE_STATIC_LIBS ON)
endif ()

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
include_directories( ${Boost_INCLUDE_DIRS} ${CRYPTO++_INCLUDE_DIR} "${CMAKE_SOURCE_DIR}/..")

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
message(STATUS "---------------------------------------")

#Handle paths nicely
include(GNUInstallDirs)

if (WITH_BINARY)
  add_executable ( "${PROJECT_NAME}-bin" ${DAEMON_SRC} )
 if(NOT MSVC) # FIXME: incremental linker file name (.ilk) collision for dll & exe
  set_target_properties("${PROJECT_NAME}-bin" PROPERTIES OUTPUT_NAME "${PROJECT_NAME}")
 endif()

  if (WITH_HARDENING AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties("${PROJECT_NAME}-bin" PROPERTIES LINK_FLAGS "-z relro -z now" )
  endif ()

  if (WITH_STATIC)
    set(BUILD_SHARED_LIBS OFF)
    set_target_properties("${PROJECT_NAME}-bin" PROPERTIES LINK_FLAGS "-static" )
  else()
    add_definitions(-DBOOST_ALL_DYN_LINK)
  endif ()

  target_link_libraries( "${PROJECT_NAME}-bin" common ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )

  install(TARGETS "${PROJECT_NAME}-bin" RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} )
  install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}-bin> DESTINATION "bin" CONFIGURATIONS DEBUG)
endif ()

if (WITH_LIBRARY)
 if (MSVC)
  # FIXME: DLL would not have any symbols unless we use __declspec(dllexport) through out the code
  add_library(${PROJECT_NAME} ${LIBRARY_SRC})
 else ()
  add_library(${PROJECT_NAME} SHARED ${LIBRARY_SRC})
  target_link_libraries( ${PROJECT_NAME} common ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES})
 endif ()
  install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()
