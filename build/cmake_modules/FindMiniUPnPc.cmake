# - Find MINIUPNPC

if(MINIUPNPC_INCLUDE_DIR)
   set(MINIUPNPC_FOUND TRUE)

else()
  find_path(MINIUPNPC_INCLUDE_DIR miniupnpc.h
      /usr/include/miniupnpc
      /usr/local/include/miniupnpc
      /opt/local/include/miniupnpc
      $ENV{SystemDrive}/miniupnpc
      ${PROJECT_SOURCE_DIR}/../../miniupnpc
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
