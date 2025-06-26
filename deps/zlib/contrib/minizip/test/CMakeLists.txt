# if we are built from with zlib, use this path's)
if(DEFINED ZLIB_BUILD_SHARED)
    set(WORK_DIR ${zlib_BINARY_DIR})
    set(inst_setup minizip_minizip_install)
else(DEFINED ZLIB_BUILD_SHARED)
    set(WORK_DIR ${minizip_BINARY_DIR})
    set(inst_setup minizip_minizip_install)
    set(ZLIB_ARG "-DZLIB_DIR=${ZLIB_DIR}")

    add_test(
        NAME minizip_install
        COMMAND ${CMAKE_COMMAND} --install ${minizip_BINARY_DIR} --prefix
                ${CMAKE_CURRENT_BINARY_DIR}/test_install --config $<CONFIG>
        WORKING_DIRECTORY ${minizip_BINARY_DIR})

    set_tests_properties(minizip_install PROPERTIES FIXTURES_SETUP
                                                    minizip_install)
endif(DEFINED ZLIB_BUILD_SHARED)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/findpackage_test)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_test)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_exclude_test)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/find_package_test.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/findpackage_test/CMakeLists.txt @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/add_subdirectory_test.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_test/CMakeLists.txt @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/add_subdirectory_exclude_test.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_exclude_test/CMakeLists.txt
    @ONLY)

# CMAKE_GENERATOR_PLATFORM doesn't work in the if
set(GENERATOR ${CMAKE_GENERATOR_PLATFORM})

if(GENERATOR)
    set(PLATFORM "-A ${GENERATOR}")
endif(GENERATOR)

#
# findpackage_test
#
add_test(
    NAME minizip_find_package_configure
    COMMAND
        ${CMAKE_COMMAND} ${PLATFORM}
        -B${CMAKE_CURRENT_BINARY_DIR}/findpackage_test_build
        -DCMAKE_BUILD_TYPE=$<CONFIG> -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_INSTALL_PREFIX=${WORK_DIR}/test/test_install ${ZLIB_ARG}
        --fresh -G "${CMAKE_GENERATOR}"
        -S${CMAKE_CURRENT_BINARY_DIR}/findpackage_test)

add_test(
    NAME minizip_find_package_build
    COMMAND ${CMAKE_COMMAND} --build . --config $<CONFIG>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/findpackage_test_build)

set_tests_properties(
    minizip_find_package_configure PROPERTIES FIXTURES_REQUIRED ${inst_setup}
                                              FIXTURES_SETUP mzfp_config)

set_tests_properties(minizip_find_package_build PROPERTIES FIXTURES_REQUIRED
                                                           mzfp_config)

#
# add_subdirectory_test
#
add_test(
    NAME minizip_add_subdirectory_configure
    COMMAND
        ${CMAKE_COMMAND} ${PLATFORM}
        -B${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_test_build
        -DCMAKE_BUILD_TYPE=$<CONFIG> -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_INSTALL_PREFIX=${WORK_DIR}/test/test_install ${ZLIB_ARG}
        --fresh -G "${CMAKE_GENERATOR}"
        -S${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_test)

add_test(
    NAME minizip_add_subdirectory_build
    COMMAND ${CMAKE_COMMAND} --build . --config $<CONFIG>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_test_build)

set_tests_properties(
    minizip_add_subdirectory_configure
    PROPERTIES FIXTURES_REQUIRED ${inst_setup} FIXTURES_SETUP mzas_config)

set_tests_properties(minizip_add_subdirectory_build PROPERTIES FIXTURES_REQUIRED
                                                               mzas_config)

#
# add_subdirectory_exclude_test
#
add_test(
    NAME minizip_add_subdirectory_exclude_configure
    COMMAND
        ${CMAKE_COMMAND} ${PLATFORM}
        -B${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_exclude_test_build
        -DCMAKE_BUILD_TYPE=$<CONFIG> -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_INSTALL_PREFIX=${WORK_DIR}/test/test_install ${ZLIB_ARG}
        --fresh -G "${CMAKE_GENERATOR}"
        -S${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_exclude_test)

add_test(
    NAME minizip_add_subdirectory_exclude_build
    COMMAND ${CMAKE_COMMAND} --build . --config $<CONFIG>
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_exclude_test_build)

set_tests_properties(
    minizip_add_subdirectory_exclude_configure
    PROPERTIES FIXTURES_REQUIRED ${inst_setup} FIXTURES_SETUP mzasx_config)

set_tests_properties(minizip_add_subdirectory_exclude_build
                     PROPERTIES FIXTURES_REQUIRED mzasx_config)
