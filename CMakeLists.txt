cmake_minimum_required(VERSION 3.12)

project(libcng-dpapi)

execute_process(
    COMMAND
    bash -c "grep 'Version:' .gear/libcng-dpapi.spec | awk -F ':' '{ print $2 }' | tr -d [:space:]"
    OUTPUT_VARIABLE LIB_CNG_DPAPI_GEAR_VERSION
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

string(REPLACE "." ";" GEAR_VERSION_LIST ${LIB_CNG_DPAPI_GEAR_VERSION})
list(GET GEAR_VERSION_LIST 0 LIB_CNG_DPAPI_VERSION_MAJOR)
list(GET GEAR_VERSION_LIST 1 LIB_CNG_DPAPI_VERSION_MINOR)
list(GET GEAR_VERSION_LIST 2 LIB_CNG_DPAPI_VERSION_PATCH)

if(UNIX)
  include(GNUInstallDirs)
else()
    message(FATAL_ERROR "System not UNIX - not implemented yet")
endif()

set(CNG_DPAPI_IN_BUILD_TREE TRUE)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

configure_file(
    "${CMAKE_MODULE_PATH}/CNGDpApiConfig.cmake.in"
    "${CMAKE_BINARY_DIR}/CNGDpApiConfig.cmake"
    IMMEDIATE @ONLY
)
install(FILES ${CMAKE_BINARY_DIR}/CNGDpApiConfig.cmake DESTINATION "${CMAKE_INSTALL_LIBDIR}/cng-dpapi")

configure_file(
    "${CMAKE_MODULE_PATH}/CNGDpApiBuildTreeSettings.cmake.in"
    "${CMAKE_BINARY_DIR}/CNGDpApiBuildTreeSettings.cmake"
    IMMEDIATE @ONLY
)

export(PACKAGE CNGDpApi)

add_subdirectory(examples)

add_subdirectory(src)

option(CNG_DPAPI_BUILD_TESTS "Build cng-dpapi tests." ON)
option(CNG_DPAPI_BUILD_EXAMPLES "Build cng-dpapi examples." ON)

enable_testing()
add_subdirectory(tests)
