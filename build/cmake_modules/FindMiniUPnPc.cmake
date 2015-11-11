# - Find MINIUPNPC

if(MINIUPNPC_INCLUDE_DIR)
   set(MINIUPNPC_FOUND TRUE)

else()
  find_path(MINIUPNPC_INCLUDE_DIR miniupnpc/miniupnpc.h
      /usr/include
      /usr/local/include
      /opt/local/include
      $ENV{SystemDrive}
      ${PROJECT_SOURCE_DIR}/../..
      )
  
  if(MINIUPNPC_INCLUDE_DIR)
    set(MINIUPNPC_FOUND TRUE)
    message(STATUS "Found MiniUPnP headers: ${MINIUPNPC_INCLUDE_DIR}")
  else()
    set(MINIUPNPC_FOUND FALSE)
    message(STATUS "MiniUPnP not found.")
  endif()

  mark_as_advanced(MINIUPNPC_INCLUDE_DIR)
  
endif()
