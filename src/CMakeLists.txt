find_package(Gkdi REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(Ndr REQUIRED IMPORTED_TARGET ndr)
pkg_check_modules(Tevent REQUIRED IMPORTED_TARGET tevent)
pkg_check_modules(DCERPC REQUIRED IMPORTED_TARGET dcerpc)
pkg_check_modules(SambaCredentials REQUIRED IMPORTED_TARGET samba-credentials)
pkg_check_modules(SambaHostconfig REQUIRED IMPORTED_TARGET samba-hostconfig)
pkg_check_modules(SambaUtil REQUIRED IMPORTED_TARGET samba-util)
pkg_check_modules(Krb5GssAPI REQUIRED IMPORTED_TARGET krb5-gssapi)

pkg_check_modules(OpenSSL REQUIRED IMPORTED_TARGET openssl)

set(LIBRARY_NAME cng-dpapi)

add_subdirectory(pkcs7)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(PUBLIC_HEADERS
    cng-dpapi_client.h
)

set(PRIVATE_HEADERS
    blob_p.h
    pkcs7_p.h
    protection_descriptor_p.h
)

set(SOURCES
    blob.c
    cng-dpapi_client.c
    pkcs7.c
    protection_descriptor.c
)

set(SOURCES ${PRIVATE_HEADERS} ${PUBLIC_HEADERS} ${SOURCES})

add_library(${LIBRARY_NAME} SHARED ${SOURCES})
target_link_libraries(${LIBRARY_NAME} PUBLIC ${GKDI_LIBRARY})
target_link_libraries(${LIBRARY_NAME} PUBLIC pkcs7)

target_include_directories(${LIBRARY_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/pkcs7")

target_link_libraries(${LIBRARY_NAME} PUBLIC
    PkgConfig::Ndr
    PkgConfig::Tevent
    PkgConfig::DCERPC
    PkgConfig::SambaCredentials
    PkgConfig::SambaHostconfig
    PkgConfig::SambaUtil
    PkgConfig::Krb5GssAPI
)

target_link_libraries(${LIBRARY_NAME} PUBLIC
    PkgConfig::OpenSSL
)

# Soname
set_target_properties(${LIBRARY_NAME} PROPERTIES VERSION "${LIB_CNG_DPAPI_GEAR_VERSION}" SOVERSION "${LIB_CNG_DPAPI_VERSION_MAJOR}")

# Prevent OverLinking
target_link_options(${LIBRARY_NAME} PRIVATE "LINKER:--as-needed")

# Installation
install(TARGETS ${LIBRARY_NAME} DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PUBLIC_HEADERS} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cng-dpapi")
