function(ZLIB_findTestEnv testName)
    set(testEnv "PATH=")

    if(MSVC OR MINGW)
        set(separator "\\\;")
    else()
        set(separator ":")
    endif()

    string(APPEND testEnv "$<TARGET_FILE_DIR:ZLIB::ZLIB>${separator}")
    string(APPEND testEnv "$ENV{PATH}")

    set_tests_properties(${testName} PROPERTIES ENVIRONMENT "${testEnv}")
endfunction()

if(ZLIB_BUILD_SHARED)
    add_executable(zlib_example example.c)
    target_link_libraries(zlib_example ZLIB::ZLIB)
    target_compile_definitions(zlib_example PRIVATE ZLIB_BUILD)
    add_test(NAME zlib_example COMMAND zlib_example)

    add_executable(minigzip minigzip.c)
    target_compile_definitions(
        minigzip PRIVATE $<$<BOOL:${HAVE___ATTR__VIS_HIDDEN}>:HAVE_HIDDEN>)
    target_link_libraries(minigzip ZLIB::ZLIB)

    if(MSVC
       OR MSYS
       OR MINGW
       OR CYGWIN)
        zlib_findtestenv(zlib_example)
    endif(
        MSVC
        OR MSYS
        OR MINGW
        OR CYGWIN)

    if(HAVE_OFF64_T)
        add_executable(zlib_example64 example.c)
        target_compile_definitions(
            zlib_example64
            PRIVATE ZLIB_BUILD
                    $<$<BOOL:${HAVE___ATTR__VIS_HIDDEN}>:HAVE_HIDDEN>)
        target_link_libraries(zlib_example64 ZLIB::ZLIB)
        add_test(NAME zlib_example64 COMMAND zlib_example64)

        if(MSVC
           OR MSYS
           OR MINGW
           OR CYGWIN)
            zlib_findtestenv(zlib_example64)
        endif(
            MSVC
            OR MSYS
            OR MINGW
            OR CYGWIN)
    endif(HAVE_OFF64_T)
endif(ZLIB_BUILD_SHARED)

if(ZLIB_BUILD_STATIC)
    add_executable(zlib_static_example example.c)
    target_link_libraries(zlib_static_example ZLIB::ZLIBSTATIC)
    target_compile_definitions(
        zlib_static_example
        PRIVATE ZLIB_BUILD
                $<$<BOOL:${HAVE___ATTR__VIS_HIDDEN}>:HAVE_HIDDEN>)
    add_test(NAME zlib_static_example COMMAND zlib_static_example)

    add_executable(static_minigzip minigzip.c)
    target_link_libraries(static_minigzip ZLIB::ZLIBSTATIC)

    if(${CMAKE_C_COMPILER_ID} STREQUAL "GNU" OR ${CMAKE_C_COMPILER_ID} STREQUAL
                                                "Clang")
        set(CFLAGS_OLD ${CMAKE_C_FLAGS})
        set({CMAKE_C_FLAGS
            ""
            CACHE STRING "" FORCE)

        if(${CMAKE_C_COMPILER_ID} STREQUAL "GNU")
            find_program(GCOV_EXECUTABLE gcov)
        endif(${CMAKE_C_COMPILER_ID} STREQUAL "GNU")

        if(${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
            set(llvm_names llvm_cov)
            list(APPEND llvm_names llvm-cov)

            foreach(ver RANGE 11 99)
                list(APPEND llvm_names llvm-cov-${ver})
            endforeach(ver RANGE 11 99)

            find_program(GCOV_EXECUTABLE NAMES ${llvm_names})
            set(llvm_option "gcov")
        endif(${CMAKE_C_COMPILER_ID} STREQUAL "Clang")

        add_executable(infcover infcover.c)
        target_link_libraries(infcover ZLIB::ZLIBSTATIC)
        target_compile_options(infcover PRIVATE -coverage)
        target_link_options(infcover PRIVATE -coverage)
        target_compile_definitions(
            infcover PRIVATE $<$<BOOL:${HAVE___ATTR__VIS_HIDDEN}>:HAVE_HIDDEN>)
        add_test(NAME zlib-coverage COMMAND infcover)
        set(INFCOVER_DIR ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/infcover.dir)
        add_test(
            NAME zlib-coverage-summary
            COMMAND
                ${GCOV_EXECUTABLE} ${llvm_option}
                ${CMAKE_CURRENT_SOURCE_DIR}/infcover.c -o
                ${INFCOVER_DIR}/infcover.c.gcda)
        set_tests_properties(zlib-coverage-summary PROPERTIES DEPENDS
                                                              zlib-coverage)
        set({CMAKE_C_FLAGS
            ${CFLAGS_OLD}
            CACHE STRING "" FORCE)
    endif(${CMAKE_C_COMPILER_ID} STREQUAL "GNU" OR ${CMAKE_C_COMPILER_ID}
                                                   STREQUAL "Clang")

    if(HAVE_OFF64_T)
        add_executable(zlib_static_example64 example.c)
        target_compile_definitions(
            zlib_static_example64
            PRIVATE ZLIB_BUILD
                    $<$<BOOL:${HAVE___ATTR__VIS_HIDDEN}>:HAVE_HIDDEN>)
        target_link_libraries(zlib_static_example64 ZLIB::ZLIBSTATIC)
        add_test(NAME zlib_static_example64 COMMAND zlib_static_example64)
    endif(HAVE_OFF64_T)
endif(ZLIB_BUILD_STATIC)

add_test(
    NAME zlib_install
    COMMAND ${CMAKE_COMMAND} --install ${zlib_BINARY_DIR} --prefix
            ${CMAKE_CURRENT_BINARY_DIR}/test_install --config $<CONFIG>
    WORKING_DIRECTORY ${zlib_BINARY_DIR})

set_tests_properties(zlib_install PROPERTIES FIXTURES_SETUP zlib_install)

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
    NAME zlib_find_package_configure
    COMMAND
        ${CMAKE_COMMAND} ${PLATFORM}
        -B${CMAKE_CURRENT_BINARY_DIR}/findpackage_test_build
        -DCMAKE_BUILD_TYPE=$<CONFIG> -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/test_install --fresh
        -G "${CMAKE_GENERATOR}" -S${CMAKE_CURRENT_BINARY_DIR}/findpackage_test)

add_test(
    NAME zlib_find_package_build
    COMMAND ${CMAKE_COMMAND} --build . --config $<CONFIG>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/findpackage_test_build)

add_test(
    NAME zlib_find_package_test
    COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIG>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/findpackage_test_build)

set_tests_properties(
    zlib_find_package_configure PROPERTIES FIXTURES_REQUIRED zlib_install
                                           FIXTURES_SETUP fp_config)

set_tests_properties(
    zlib_find_package_build PROPERTIES FIXTURES_REQUIRED fp_config
                                       FIXTURES_SETUP fp_build)

set_tests_properties(
    zlib_find_package_test PROPERTIES FIXTURES_REQUIRED fp_build ENVIRONMENT
                                      CTEST_OUTPUT_ON_FAILURE=1)

#
# add_subdirectory_test
#
add_test(
    NAME zlib_add_subdirectory_configure
    COMMAND
        ${CMAKE_COMMAND} ${PLATFORM}
        -B${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_test_build
        -DCMAKE_BUILD_TYPE=$<CONFIG> -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/test_install --fresh
        -G "${CMAKE_GENERATOR}" -S${CMAKE_CURRENT_BINARY_DIR}/findpackage_test)

add_test(
    NAME zlib_add_subdirectory_build
    COMMAND ${CMAKE_COMMAND} --build . --config $<CONFIG>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_test_build)

add_test(
    NAME zlib_add_subdirectory_test
    COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIG>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_test_build)

set_tests_properties(
    zlib_add_subdirectory_configure PROPERTIES FIXTURES_REQUIRED zlib_install
                                               FIXTURES_SETUP as_config)

set_tests_properties(
    zlib_add_subdirectory_build PROPERTIES FIXTURES_REQUIRED as_config
                                           FIXTURES_SETUP as_build)

set_tests_properties(
    zlib_add_subdirectory_test PROPERTIES FIXTURES_REQUIRED as_build
                                          ENVIRONMENT CTEST_OUTPUT_ON_FAILURE=1)

#
# add_subdirectory_exclude_test
#
add_test(
    NAME zlib_add_subdirectory_exclude_configure
    COMMAND
        ${CMAKE_COMMAND} ${PLATFORM}
        -B${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_exclude_test_build
        -DCMAKE_BUILD_TYPE=$<CONFIG> -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/test_install --fresh
        -G "${CMAKE_GENERATOR}" -S${CMAKE_CURRENT_BINARY_DIR}/findpackage_test)

add_test(
    NAME zlib_add_subdirectory_exclude_build
    COMMAND ${CMAKE_COMMAND} --build . --config $<CONFIG>
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_exclude_test_build)

add_test(
    NAME zlib_add_subdirectory_exclude_test
    COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIG>
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_exclude_test_build)

set_tests_properties(
    zlib_add_subdirectory_exclude_configure
    PROPERTIES FIXTURES_REQUIRED zlib_install FIXTURES_SETUP asx_config)

set_tests_properties(
    zlib_add_subdirectory_exclude_build PROPERTIES FIXTURES_REQUIRED as_config
                                                   FIXTURES_SETUP asx_build)

set_tests_properties(
    zlib_add_subdirectory_exclude_test
    PROPERTIES FIXTURES_REQUIRED asx_build ENVIRONMENT
               CTEST_OUTPUT_ON_FAILURE=1)
