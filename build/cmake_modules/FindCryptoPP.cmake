# - Find Crypto++

if(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
   set(CRYPTO++_FOUND TRUE)

else(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
  find_path(CRYPTO++_INCLUDE_DIR cryptlib.h
      /usr/include/crypto++
      /usr/include/cryptopp
      /usr/local/include/crypto++
      /usr/local/include/cryptopp
      /opt/local/include/crypto++
      /opt/local/include/cryptopp
      $ENV{SystemDrive}/Crypto++/include
      $ENV{CRYPTOPP}
      $ENV{CRYPTOPP}/include
      ${PROJECT_SOURCE_DIR}/../../cryptopp
      )

  find_library(CRYPTO++_LIBRARIES NAMES cryptopp
      PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      $ENV{SystemDrive}/Crypto++/lib
      $ENV{CRYPTOPP}/lib
      )

  if(MSVC AND NOT CRYPTO++_LIBRARIES) # Give a chance for MSVC multiconfig
      if(CMAKE_SIZEOF_VOID_P EQUAL 8)
          set(PLATFORM x64)
      else()
          set(PLATFORM Win32)
      endif()
      find_library(CRYPTO++_LIBRARIES_RELEASE NAMES cryptlib cryptopp
          PATHS
          $ENV{CRYPTOPP}/Win32/Output/Release
          ${PROJECT_SOURCE_DIR}/../../cryptopp/${PLATFORM}/Output/Release
      )
      find_library(CRYPTO++_LIBRARIES_DEBUG NAMES cryptlib cryptopp
          PATHS
          $ENV{CRYPTOPP}/Win32/Output/Debug
          ${PROJECT_SOURCE_DIR}/../../cryptopp/${PLATFORM}/Output/Debug
      )
      set(CRYPTO++_LIBRARIES
          debug ${CRYPTO++_LIBRARIES_DEBUG}
          optimized ${CRYPTO++_LIBRARIES_RELEASE}
          CACHE PATH "Path to Crypto++ library" FORCE
      )
  endif()

  if(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
    set(CRYPTO++_FOUND TRUE)
    message(STATUS "Found Crypto++: ${CRYPTO++_INCLUDE_DIR}, ${CRYPTO++_LIBRARIES}")
  else(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
    set(CRYPTO++_FOUND FALSE)
    message(STATUS "Crypto++ not found.")
  endif(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)

  mark_as_advanced(CRYPTO++_INCLUDE_DIR CRYPTO++_LIBRARIES)

endif(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
