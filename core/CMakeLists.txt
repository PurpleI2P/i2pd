set(CORE_SRC
  "transport/NTCPSession.cpp"
  "transport/SSU.cpp"
  "transport/SSUData.cpp"
  "transport/SSUSession.cpp"
  "transport/Transports.cpp"
  "crypto/CryptoConst.cpp"
  "crypto/aes.cpp"
  "crypto/Signature.cpp"
  "util/base64.cpp"
  "util/util.cpp"
  "util/Log.cpp"
  "tunnel/TransitTunnel.cpp"
  "tunnel/Tunnel.cpp"
  "tunnel/TunnelGateway.cpp"
  "tunnel/TunnelEndpoint.cpp"
  "tunnel/TunnelPool.cpp"
  "tunnel/TunnelCrypto.cpp"
  "AddressBook.cpp"	
  "Garlic.cpp"
  "I2NPProtocol.cpp"
  "Identity.cpp"
  "LeaseSet.cpp"
  "NetDbRequests.cpp"	
  "NetDb.cpp"
  "Profiling.cpp"
  "RouterContext.cpp"
  "RouterInfo.cpp"
  "Streaming.cpp"
  "Destination.cpp"	
  "Datagram.cpp"
  "UPnP.cpp"
  "Reseed.cpp"
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND CORE_SRC "util/I2PEndian.cpp")
endif()

include_directories(".")

# Library building
if(WITH_LIBRARY)
    add_library(${CORE_NAME} ${CORE_SRC})
    target_link_libraries(
        ${CORE_NAME} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES}
    )

    install(
        TARGETS ${CORE_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

