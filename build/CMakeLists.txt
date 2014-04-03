
cmake_minimum_required ( VERSION 2.8 )

project ( i2pd )

set ( SRC_DIR ".." )
set ( INC_DIR ".." )

add_definitions ( "-std=c++0x -Wall" )

set ( SOURCES
        AddressBook.cpp
        Garlic.cpp
        HTTPServer.cpp
        i2p.cpp
        Identity.cpp
        Log.cpp
        NTCPSession.cpp
        RouterContext.cpp
        SSU.cpp
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
)

set ( HEADERS
        AddressBook.h
        Garlic.h
        HTTPServer.h
        Identity.h
        Log.h
        NTCPSession.h
        RouterContext.h
        SSU.h
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
)

source_group ("Header Files" FILES ${HEADERS})
source_group ("Source Files" FILES ${SOURCES})

find_package ( Threads REQUIRED )

find_package ( Boost COMPONENTS system filesystem regex program_options REQUIRED )

set ( CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules" )
find_package ( CryptoPP REQUIRED )

include_directories ( ${Boost_INCLUDE_DIRS} ${CryptoPP_INCLUDE_DIRS})


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

target_link_libraries( ${PROJECT_NAME} ${Boost_LIBRARIES} ${CryptoPP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
