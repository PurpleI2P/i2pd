set(BENCHMARK_SRC
  "main.cpp"
)

if(WITH_BENCHMARK)
    add_executable(${BENCHMARK_NAME} ${BENCHMARK_SRC})
    target_link_libraries(
        ${BENCHMARK_NAME} ${CORE_NAME} ${DL_LIB} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
    )
    install(TARGETS
        ${BENCHMARK_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()
