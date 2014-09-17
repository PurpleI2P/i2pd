cmake_minimum_required ( VERSION 2.8 )
project ( "i2pd" )

# configurale options
option(WITH_AESNI     "Use AES-NI instructions set" OFF)
option(WITH_HARDENING "Use hardening compiler flags" OFF)

# paths
set ( CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules" )
set ( CMAKE_SOURCE_DIR ".." )

set (SOURCES
  "${CMAKE_SOURCE_DIR}/AddressBook.cpp"
  "${CMAKE_SOURCE_DIR}/CryptoConst.cpp"
  "${CMAKE_SOURCE_DIR}/Daemon.cpp"
  "${CMAKE_SOURCE_DIR}/Garlic.cpp"
  "${CMAKE_SOURCE_DIR}/HTTPProxy.cpp"
  "${CMAKE_SOURCE_DIR}/HTTPServer.cpp"
  "${CMAKE_SOURCE_DIR}/I2NPProtocol.cpp"
  "${CMAKE_SOURCE_DIR}/I2PTunnel.cpp"
  "${CMAKE_SOURCE_DIR}/Identity.cpp"
  "${CMAKE_SOURCE_DIR}/LeaseSet.cpp"
  "${CMAKE_SOURCE_DIR}/Log.cpp"
  "${CMAKE_SOURCE_DIR}/NTCPSession.cpp"
  "${CMAKE_SOURCE_DIR}/NetDb.cpp"
  "${CMAKE_SOURCE_DIR}/Reseed.cpp"
  "${CMAKE_SOURCE_DIR}/RouterContext.cpp"
  "${CMAKE_SOURCE_DIR}/RouterInfo.cpp"
  "${CMAKE_SOURCE_DIR}/SOCKS.cpp"
  "${CMAKE_SOURCE_DIR}/SSU.cpp"
  "${CMAKE_SOURCE_DIR}/SSUData.cpp"
  "${CMAKE_SOURCE_DIR}/Streaming.cpp"
  "${CMAKE_SOURCE_DIR}/TransitTunnel.cpp"
  "${CMAKE_SOURCE_DIR}/Tunnel.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelGateway.cpp"
  "${CMAKE_SOURCE_DIR}/Transports.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelEndpoint.cpp"
  "${CMAKE_SOURCE_DIR}/TunnelPool.cpp"
  "${CMAKE_SOURCE_DIR}/UPnP.cpp"
  "${CMAKE_SOURCE_DIR}/aes.cpp"
  "${CMAKE_SOURCE_DIR}/base64.cpp"
  "${CMAKE_SOURCE_DIR}/i2p.cpp"
  "${CMAKE_SOURCE_DIR}/util.cpp"
)

file (GLOB HEADERS "${CMAKE_SOURCE_DIR}/*.h")

# MSVS grouping
source_group ("Header Files" FILES ${HEADERS})
source_group ("Source Files" FILES ${SOURCES})

# Default build is Debug
if (CMAKE_BUILD_TYPE STREQUAL "Release")
  add_definitions( "-pedantic" )
else ()
  set(CMAKE_BUILD_TYPE Debug)
endif ()

# compiler flags customization (by vendor)
add_definitions ( "-Wall -Wextra" )
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_definitions( "-std=c++0x" )
  if (WITH_HARDENING)
    add_definitions( "-D_FORTIFY_SOURCE=2" )
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security -Werror=format-security" )
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector --param ssp-buffer-size=4" )
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -pie" )
  endif ()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  add_definitions( "-std=c++11" )
endif ()

# compiler flags customization (by system)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list (APPEND SOURCES "../DaemonLinux.cpp")
elseif (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  list (APPEND SOURCES "../DaemonLinux.cpp")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list (APPEND SOURCES "../DaemonWin32.cpp")
endif ()

if (WITH_AESNI)
  add_definitions ( "-maes -DAESNI" )
endif()

# libraries
find_package ( Threads REQUIRED )

find_package ( Boost COMPONENTS system filesystem regex program_options REQUIRED )
if(NOT DEFINED Boost_INCLUDE_DIRS)
  message(SEND_ERROR "Boost is not found, or your boost version was bellow 1.46. Please download Boost!")
endif()

find_package ( CryptoPP REQUIRED )
if(NOT DEFINED CRYPTO++_INCLUDE_DIR)
  message(SEND_ERROR "Could not find Crypto++. Please download and install it first!")
endif()

# load includes
include_directories( ${Boost_INCLUDE_DIRS} ${CRYPTO++_INCLUDE_DIR})

# show summary
message(STATUS "---------------------------------------")
message(STATUS "Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler           : ${CMAKE_CXX_COMPILER}")
message(STATUS "Install prefix:    : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Options:")
message(STATUS "  AESNI            : ${WITH_AESNI}")
message(STATUS "  HARDENING        : ${WITH_HARDENING}")
message(STATUS "---------------------------------------")

add_executable ( ${PROJECT_NAME} ${SOURCES} )

if (WITH_HARDENING)
  set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-z relro -z now" )
endif ()

target_link_libraries( ${PROJECT_NAME} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )

install(TARGETS i2pd RUNTIME DESTINATION "bin")
