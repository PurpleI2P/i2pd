
include_directories(
  ../libi2pd
  ${Boost_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
)


set(LIBS
  libi2pd
  ${Boost_LIBRARIES}
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  Threads::Threads
  ${CMAKE_REQUIRED_LIBRARIES}
)

add_library(fuzzing OBJECT
	fuzzing_impl.cpp
	fuzzing_throttle.cpp
	fuzzing.h)

link_libraries(fuzzing)

set(FUZZERS
	Base32ToByteStream_fuzzer
	Base64ToByteStream_fuzzer
	BlindedPublicKey_fuzzer
	ByteStreamToBase32_fuzzer
	ByteStreamToBase64_fuzzer
	HandleI2NPMessage_fuzzer
	IdentityEx_fuzzer
	LeaseSet_fuzzer
	LeaseSet2_fuzzer
	Mapping_fuzzer
	NetDb-AddRouterInfo_fuzzer
	NetDb-PostDatabaseSearchReplyMsg_fuzzer
	NetDb-PostI2NPMsg_fuzzer
	RouterContext-DecryptTunnelBuildRecord_fuzzer
	RouterContext-ProcessDeliveryStatusMessage_fuzzer
	RouterContext-ProcessGarlicMessage_fuzzer
	RouterInfo_fuzzer
	ToBase64Standard_fuzzer
)

string(REPLACE "fuzzer-no-link" "fuzzer" _LINK_FLAGS "${_SANITIZE_FLAGS}")

foreach(F IN LISTS FUZZERS)
	add_executable(${F} ${F}.cpp)
	target_link_libraries(${F} ${LIBS})
	target_link_options(${F} PRIVATE ${_LINK_FLAGS})
endforeach()

