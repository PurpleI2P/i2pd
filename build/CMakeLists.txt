cmake_minimum_required ( VERSION 2.8 )
project ( i2pd )

# Default build is Debug
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")

set ( SRC_DIR ".." )
set ( INC_DIR ".." )


add_definitions ( "-std=c++0x -Wall" )

set ( SOURCES
		CryptoConst.cpp	
        AddressBook.cpp
        Garlic.cpp
        HTTPServer.cpp
        i2p.cpp
        Identity.cpp
        Log.cpp
        NTCPSession.cpp
        RouterContext.cpp
        SSU.cpp
	SSUData.cpp
        TransitTunnel.cpp
        Tunnel.cpp
        TunnelGateway.cpp
        UPnP.cpp
        base64.cpp
        HTTPProxy.cpp
        I2NPProtocol.cpp
        LeaseSet.cpp
        NetDb.cpp
        Reseed.cpp
        RouterInfo.cpp
        Streaming.cpp
        Transports.cpp
        TunnelEndpoint.cpp
        TunnelPool.cpp
        util.cpp
        aes.cpp
	Daemon.cpp
    SOCKS.cpp
)

set ( HEADERS
		CryptoConst.h
        AddressBook.h
        Garlic.h
        HTTPServer.h
        Identity.h
        Log.h
        NTCPSession.h
        RouterContext.h
        SSU.h
	SSUData.h
        TransitTunnel.h
        Tunnel.h
        TunnelGateway.h
        UPnP.h
        base64.h
        HTTPProxy.h
        I2NPProtocol.h
        LeaseSet.h
        NetDb.h
        Reseed.h
        RouterInfo.h
        Streaming.h
        Transports.h
        TunnelEndpoint.h
        TunnelPool.h
        util.h
        aes.h
	Daemon.h
    SOCKS.h
)

if (WIN32)
	list (APPEND SOURCES DeamonWin32.cpp)
else ()
	list (APPEND SOURCES DaemonLinux.cpp)
endif ()



source_group ("Header Files" FILES ${HEADERS})
source_group ("Source Files" FILES ${SOURCES})

set ( CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules" )

find_package ( Threads REQUIRED )

find_package ( Boost COMPONENTS system filesystem regex program_options REQUIRED )

find_package ( CryptoPP REQUIRED )

# Check for libraries
if(NOT DEFINED Boost_INCLUDE_DIRS)
    message(FATAL_ERROR "Boost is not found, or your boost version was bellow 1.46. Please download Boost!")
    return()
endif()

if(NOT DEFINED CRYPTO++_INCLUDE_DIR)
    message(FATAL_ERROR "Could not find Crypto++. Please download and install it first!")
    return()
endif()


# End checks


include_directories ( ${Boost_INCLUDE_DIRS} ${CRYPTO++_INCLUDE_DIR})


unset ( TMP )
foreach ( src ${SOURCES} )
        list ( APPEND TMP "${SRC_DIR}/${src}" )
endforeach ()
set ( SOURCES ${TMP} )

unset ( TMP )
foreach ( hdr ${HEADERS} )
        list ( APPEND TMP "${INC_DIR}/${hdr}" )
endforeach ()
set ( HEADERS ${TMP} )


add_executable ( ${PROJECT_NAME} WIN32 ${HEADERS} ${SOURCES} )

target_link_libraries( ${PROJECT_NAME} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
