# Find Crypto++ library
#
# Output variables :
#       CryptoPP_FOUND
#       CryptoPP_INCLUDE_DIRS
#       CryptoPP_LIBRARIES
#


FIND_PATH( CryptoPP_INCLUDE_DIR cryptopp/dsa.h )

FIND_LIBRARY( CryptoPP_LIBRARY NAMES cryptopp )

# handle the QUIETLY and REQUIRED arguments and set CRYPTOPP_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(${CMAKE_ROOT}/Modules/FindPackageHandleStandardArgs.cmake)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CryptoPP  DEFAULT_MSG  CryptoPP_LIBRARY  CryptoPP_INCLUDE_DIR)

set ( CryptoPP_FOUND FALSE )

if ( ${CRYPTOPP_FOUND} )
        set ( CryptoPP_FOUND TRUE )
        set ( CryptoPP_INCLUDE_DIRS ${CryptoPP_INCLUDE_DIR} )
        set ( CryptoPP_LIBRARIES ${CryptoPP_LIBRARY} )
endif ()

MARK_AS_ADVANCED(CryptoPP_INCLUDE_DIR CryptoPP_LIBRARY)        

