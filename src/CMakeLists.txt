# projects globals names
SET(SNIFFER_NAME sniffer CACHE STRING "Stream process name")
SET(SNIFFER_COMMON ${SNIFFER_NAME}_common)

SET(PROTOCOL_HEADERS
  ${CMAKE_SOURCE_DIR}/src/protocol/protocol.h
  ${CMAKE_SOURCE_DIR}/src/protocol/types.h
)
SET(PROTOCOL_SOURCES
  ${CMAKE_SOURCE_DIR}/src/protocol/protocol.cpp
  ${CMAKE_SOURCE_DIR}/src/protocol/types.cpp
)

SET(DAEMON_CLIENT_HEADERS
  ${CMAKE_SOURCE_DIR}/src/daemon_client/daemon_client.h
  ${CMAKE_SOURCE_DIR}/src/daemon_client/daemon_commands.h
  ${CMAKE_SOURCE_DIR}/src/daemon_client/common_commands.h
  ${CMAKE_SOURCE_DIR}/src/daemon_client/slave_master_commands.h
  ${CMAKE_SOURCE_DIR}/src/daemon_client/daemon_server.h
)
SET(DAEMON_CLIENT_SOURCES
  ${CMAKE_SOURCE_DIR}/src/daemon_client/daemon_client.cpp
  ${CMAKE_SOURCE_DIR}/src/daemon_client/common_commands.cpp
  ${CMAKE_SOURCE_DIR}/src/daemon_client/daemon_commands.cpp
  ${CMAKE_SOURCE_DIR}/src/daemon_client/slave_master_commands.cpp
  ${CMAKE_SOURCE_DIR}/src/daemon_client/daemon_server.cpp
)

SET(COMMANDS_INFO_HEADERS
  ${CMAKE_SOURCE_DIR}/src/commands_info/activate_info.h
  ${CMAKE_SOURCE_DIR}/src/commands_info/license_info.h
  ${CMAKE_SOURCE_DIR}/src/commands_info/stop_service_info.h
  ${CMAKE_SOURCE_DIR}/src/commands_info/entries_info.h
)

SET(COMMANDS_INFO_SOURCES
  ${CMAKE_SOURCE_DIR}/src/commands_info/activate_info.cpp
  ${CMAKE_SOURCE_DIR}/src/commands_info/license_info.cpp
  ${CMAKE_SOURCE_DIR}/src/commands_info/stop_service_info.cpp
  ${CMAKE_SOURCE_DIR}/src/commands_info/entries_info.cpp
)

SET(GLOBAL_HEADERS
  ${CMAKE_SOURCE_DIR}/src/types.h
  ${CMAKE_SOURCE_DIR}/src/process_wrapper.h
  ${CMAKE_SOURCE_DIR}/src/utils.h
  ${CMAKE_SOURCE_DIR}/src/entry.h
)
SET(GLOBAL_SOURCES
  ${CMAKE_SOURCE_DIR}/src/types.cpp
  ${CMAKE_SOURCE_DIR}/src/process_wrapper.cpp
  ${CMAKE_SOURCE_DIR}/src/utils.cpp
  ${CMAKE_SOURCE_DIR}/src/entry.cpp
)

SET(SNIFFER_HEADERS
  ${CMAKE_SOURCE_DIR}/src/sniffer/isniffer.h
  ${CMAKE_SOURCE_DIR}/src/sniffer/isniffer_observer.h
  ${CMAKE_SOURCE_DIR}/src/sniffer/live_sniffer.h
  ${CMAKE_SOURCE_DIR}/src/sniffer/file_sniffer.h
)

SET(SNIFFER_SOURCE
  ${CMAKE_SOURCE_DIR}/src/sniffer/isniffer.cpp
  ${CMAKE_SOURCE_DIR}/src/sniffer/isniffer_observer.cpp
  ${CMAKE_SOURCE_DIR}/src/sniffer/live_sniffer.cpp
  ${CMAKE_SOURCE_DIR}/src/sniffer/file_sniffer.cpp
)

SET(SDS_SOURCES
  ${CMAKE_SOURCE_DIR}/src/third-party/sds/sds.c
  ${CMAKE_SOURCE_DIR}/src/third-party/sds/sds_fasto.c
)

FIND_PACKAGE(Common REQUIRED)
FIND_PACKAGE(JSON-C REQUIRED)

IF(OS_WINDOWS)
  SET(PLATFORM_HEADER)
  SET(PLATFORM_SOURCES)
  SET(PLATFORM_LIBRARIES)
ELSEIF(OS_POSIX)
  SET(PLATFORM_HEADER)
  SET(PLATFORM_SOURCES)
  SET(PLATFORM_LIBRARIES pthread)
ENDIF(OS_WINDOWS)

SET(SNIFFER_COMMON_SOURCES
  ${PROTOCOL_HEADERS} ${PROTOCOL_SOURCES}
  ${DAEMON_CLIENT_HEADERS} ${DAEMON_CLIENT_SOURCES}
  ${COMMANDS_INFO_HEADERS} ${COMMANDS_INFO_SOURCES}
  ${SNIFFER_HEADERS} ${SNIFFER_SOURCE}
  ${GLOBAL_HEADERS} ${GLOBAL_SOURCES}
)
SET(SNIFFER_COMMON_LIBRARIES ${SNIFFER_COMMON_LIBRARIES} ${JSONC_LIBRARIES} ${COMMON_BASE_LIBRARY})
SET(PRIVATE_INCLUDE_DIRECTORIES_COMMON
  ${PRIVATE_INCLUDE_DIRECTORIES_COMMON}
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/third-party/sds
)

ADD_LIBRARY(${SNIFFER_COMMON} STATIC ${SNIFFER_COMMON_SOURCES})
TARGET_INCLUDE_DIRECTORIES(${SNIFFER_COMMON} PRIVATE ${PRIVATE_INCLUDE_DIRECTORIES_COMMON})
TARGET_LINK_LIBRARIES(${SNIFFER_COMMON} ${SNIFFER_COMMON_LIBRARIES})

IF(BUILD_SERVICE)
  ADD_SUBDIRECTORY(service)
ENDIF(BUILD_SERVICE)

IF(BUILD_SNIFFER)
  ADD_SUBDIRECTORY(client)
ENDIF(BUILD_SNIFFER)
