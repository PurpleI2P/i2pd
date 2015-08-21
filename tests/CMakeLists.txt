set(TESTS_SRC
  "Base64.cpp"
  "Crypto.cpp"
  "Identity.cpp"
  "Utility.cpp"
)


if(WITH_TESTS)
    find_package(Boost COMPONENTS
        system filesystem regex program_options date_time thread chrono
        unit_test_framework REQUIRED
    )
  
    add_executable(i2pd_tests ${TESTS_SRC})
    target_link_libraries(
      i2pd_tests core ${DL_LIB} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES}
      ${CMAKE_THREAD_LIBS_INIT}
    )

    enable_testing()
    add_test(i2pdTest i2pd_tests)
endif()
