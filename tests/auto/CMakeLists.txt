find_package(CNGDpApi)

set(TEST_NAME
    cng_dpapi_test
)

add_executable(${TEST_NAME} cng_dpapi_test.c)

add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
target_include_directories(${TEST_NAME} PRIVATE ${CNG_DPAPI_INCLUDE_DIR})
target_link_directories(${TEST_NAME} PRIVATE ${CNG_DPAPI_LIBRARY_DIR})
target_link_libraries(${TEST_NAME} PRIVATE ${CNG_DPAPI_LIBRARY})
target_link_libraries(${TEST_NAME} PRIVATE ldap lber)
