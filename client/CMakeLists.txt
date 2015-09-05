set(CLIENT_SRC
  "BOB.cpp"	
  "ClientContext.cpp"
  "Daemon.cpp"
  "HTTPProxy.cpp"
  "HTTPServer.cpp"
  "I2PService.cpp"
  "i2pcontrol/I2PControl.cpp"	
  "i2pcontrol/I2PControlServer.cpp"	
  "I2PTunnel.cpp"
  "SAM.cpp"
  "SOCKS.cpp"
  "i2p.cpp"
)

include_directories(".")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND CLIENT_SRC "DaemonLinux.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    list(APPEND CLIENT_SRC "DaemonLinux.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND CLIENT_SRC "DaemonLinux.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    list(APPEND CLIENT_SRC "DaemonLinux.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND CLIENT_SRC "DaemonWin32.cpp")
    list(APPEND CLIENT_SRC "Win32Service.cpp")
endif()

if(WITH_BINARY)
    add_executable(${CLIENT_NAME} ${CLIENT_SRC})
    if(NOT MSVC) # FIXME: incremental linker file name (.ilk) collision for dll & exe
        set_target_properties(${CLIENT_NAME} PROPERTIES OUTPUT_NAME "${PROJECT_NAME}")
        if(WITH_STATIC)
            set_target_properties(${CLIENT_NAME} PROPERTIES LINK_FLAGS "-static" )
        endif()
    endif()

    if(WITH_HARDENING AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set_target_properties(${CLIENT_NAME} PROPERTIES LINK_FLAGS "-z relro -z now")
    endif()

    # FindBoost pulls pthread for thread which is broken for static linking
    # (at least on Ubuntu 15.04)
    list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
    if(${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
        list(REMOVE_AT Boost_LIBRARIES -1)
    endif()
    target_link_libraries(
        ${CLIENT_NAME} ${CORE_NAME}
        ${DL_LIB} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
    )

    install(TARGETS
        ${CLIENT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(MSVC)
        install(FILES
            $<TARGET_PDB_FILE:${CLIENT_NAME}> DESTINATION "bin" CONFIGURATIONS DEBUG
        )
    endif()
endif()
