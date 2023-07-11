
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
	fuzzing_impl.cc
	fuzzing_throttle.cc
	fuzzing.h)

link_libraries(fuzzing)

set(FUZZERS
	Base32ToByteStream
	Base64ToByteStream
	BlindedPublicKey
	ByteStreamToBase32
	ByteStreamToBase64
	HandleI2NPMessage
	IdentityEx
	LeaseSet
	LeaseSet2
	NetDb-AddRouterInfo
	NetDb-HandleDatabaseSearchReplyMsg
	NetDb-HandleDatabaseStoreMsg
	NetDb-HandleDatabaseLookupMsg
	NetDb-HandleNTCP2RouterInfoMsg
	NetDb-PostI2NPMsg
	RouterContext-DecryptTunnelBuildRecord
	RouterContext-ProcessDeliveryStatusMessage
	RouterContext-ProcessGarlicMessage
)

string(REPLACE "fuzzer-no-link" "fuzzer" _LINK_FLAGS "${_SANITIZE_FLAGS}")

foreach(F IN LISTS FUZZERS)
	add_executable(fuzz-${F} fuzz-${F}.cc)
	target_link_libraries(fuzz-${F} ${LIBS})
	target_link_options(fuzz-${F} PRIVATE ${_LINK_FLAGS})
endforeach()

