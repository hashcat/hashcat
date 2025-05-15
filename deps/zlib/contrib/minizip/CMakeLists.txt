cmake_minimum_required(VERSION 3.12...3.31)

project(
    minizip
    VERSION 1.0.0
    LANGUAGES C
    DESCRIPTION "A library for creating zipfiles based in zlib"
    HOMEPAGE_URL "https://www.winimage.com/zLibDll/minizip.html")

if(CMAKE_SIZEOF_VOID_P LESS 8 AND NOT MINGW)
    message(WARNING "libminizip needs 64bit - stopping here")
    return()
endif(CMAKE_SIZEOF_VOID_P LESS 8 AND NOT MINGW)

# ============================================================================
# CPack
# ============================================================================
set(CPACK_PACKAGE_VENDOR "zlib-Project")
set(CPACK_PACKAGE_DESCRIPTION_FILE ${minizip_SOURCE_DIR}/MiniZip64_info.txt)
set(CPACK_RESOURCE_FILE_LICENSE ${minizip_SOURCE_DIR}/../../LICENSE)
set(CPACK_RESOURCE_FILE_README ${minizip_SOURCE_DIR}/MiniZip64_info.txt)

# ============================================================================
# configuration
# ============================================================================
option(MINIZIP_BUILD_SHARED "Enable building minizip shared library" ON)
option(MINIZIP_BUILD_STATIC "Enable building minizip static library" ON)
option(MINIZIP_BUILD_TESTING "Enable testing of minizip" ON)
option(MINIZIP_ENABLE_BZIP2 "Build minizip withj bzip2 support" ON)
option(MINIZIP_INSTALL "Enable installation of minizip" ON)

if(MINGW)
    option(MINIZIP_INSTALL_COMPAT_DLL "Install a copy as libminizip-1.dll" ON)
endif(MINGW)

include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CMakePackageConfigHelpers)
include(CheckTypeSize)
include(GNUInstallDirs)

if(NOT CPACK_INCLUDED)
    include(CPack)
endif(NOT CPACK_INCLUDED)

if(MINIZIP_ENABLE_BZIP2)
    find_package(BZip2 REQUIRED)
endif(MINIZIP_ENABLE_BZIP2)

#
# Check for fopen64
#
check_function_exists(fopen64 HAVE_FOPEN64)

#
# Check for fseeko
#
check_function_exists(fseeko HAVE_FSEEKO)

#
# Check for unistd.h
#
check_include_file(unistd.h HAVE_UNISTD_H)

#
# Check to see if we have large file support
#
set(CMAKE_REQUIRED_DEFINITIONS -D_LARGEFILE64_SOURCE=1)
check_type_size(off64_t OFF64_T)
unset(CMAKE_REQUIRED_DEFINITIONS) # clear variable

#
# Check visibility attribute is supported
#
if(MSVC)
    set(CMAKE_REQUIRED_FLAGS "-WX")
else(MSVC)
    set(CMAKE_REQUIRED_FLAGS "-WError")
endif(MSVC)

check_c_source_compiles(
    "
        #include <stdlib.h>
        static void f(void) __attribute__ ((visibility(\"hidden\")));
        int main(void) {return 0;}
    "
    HAVE___ATTR__VIS_HIDDEN)

unset(CMAKE_REQUIRED_FLAGS)

if(NOT TARGET ZLIB::ZLIB)
    find_package(ZLIB REQUIRED CONFIG)
endif(NOT TARGET ZLIB::ZLIB)

set(LIBMINIZIP_SRCS ioapi.c mztools.c unzip.c zip.c)

set(LIBMINIZIP_HDRS crypt.h ints.h ioapi.h mztools.h unzip.h zip.h)

set(MINIZIP_SRCS ioapi.c $<$<BOOL:${WIN32}>:iowin32.c> minizip.c zip.c)

set(MINIZIP_HDRS crypt.h ints.h ioapi.h $<$<BOOL:${WIN32}>:iowin32.h> skipset.h
                 zip.h)

set(MINIUNZIP_SRCS ioapi.c $<$<BOOL:${WIN32}>:iowin32.c> miniunz.c unzip.c
                   zip.c)

set(MINIUNZIP_HDRS
    crypt.h
    ints.h
    ioapi.h
    $<$<BOOL:${WIN32}>:iowin32.h>
    skipset.h
    unzip.h
    zip.h)

if(WIN32 OR CYGWIN)
    set(minizip_static_suffix "s")
    set(CMAKE_DEBUG_POSTFIX "d")
endif(WIN32 OR CYGWIN)

if(MINIZIP_BUILD_SHARED)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
    add_library(libminizip SHARED ${LIBMINIZIP_SRCS} ${LIBMINIZIP_HDRS})
    add_library(MINIZIP::minizip ALIAS libminizip)
    target_include_directories(
        libminizip PUBLIC $<BUILD_INTERFACE:${minizip_SOURCE_DIR}>
                          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_compile_definitions(
        libminizip
        PRIVATE $<$<BOOL:${MSVC}>:_CRT_SECURE_NO_WARNINGS>
                $<$<BOOL:${HAVE___ATTR__VIS_HIDDEN}>:HAVE_HIDDEN>
                $<$<BOOL:${HAVE_UNISTD_H}>:HAVE_UNISTD_H=1>
        PUBLIC $<$<BOOL:${HAVE_OFF64_T}>:_LARGEFILE64_SOURCE=1>
                $<$<BOOL:${BZIP2_FOUND}>:HAVE_BZIP2=1>
                $<$<BOOL:NOT:${HAVE_FOPEN64}>:USE_FILE32API=1>)

    if(NOT CYGWIN)
        set_target_properties(libminizip PROPERTIES SOVERSION
                                                    ${minizip_VERSION_MAJOR})
    endif(NOT CYGWIN)

    set_target_properties(
        libminizip
        PROPERTIES EXPORT_NAME minizip
                   OUTPUT_NAME minizip
                   VERSION ${minizip_VERSION}
                   SOVERSION ${minizip_VERSION_MAJOR})

    target_link_libraries(libminizip
        PUBLIC ZLIB::ZLIB
            $<$<BOOL:${BZIP2_FOUND}>:BZip2::BZip2>)

    add_executable(minizip ${MINIZIP_SRCS} ${MINIZIP_HDRS})
    set_target_properties(minizip PROPERTIES EXPORT_NAME minizip_executable)
    target_compile_definitions(
        minizip PRIVATE $<$<BOOL:${MSVC}>:_CRT_SECURE_NO_WARNINGS>)
    target_link_libraries(minizip PRIVATE MINIZIP::minizip)
    add_executable(miniunzip ${MINIUNZIP_SRCS} ${MINIUNZIP_HDRS})
    set_target_properties(miniunzip PROPERTIES EXPORT_NAME miniunzip_executable)
    target_compile_definitions(
        miniunzip PRIVATE $<$<BOOL:${MSVC}>:_CRT_SECURE_NO_WARNINGS>)
    target_link_libraries(miniunzip PRIVATE MINIZIP::minizip)
endif(MINIZIP_BUILD_SHARED)

if(MINIZIP_BUILD_STATIC)
    add_library(libminizipstatic STATIC ${LIBMINIZIP_SRCS} ${LIBMINIZIP_HDRS})
    add_library(MINIZIP::minizipstatic ALIAS libminizipstatic)
    target_include_directories(
        libminizipstatic
        PUBLIC $<BUILD_INTERFACE:${minizip_SOURCE_DIR}>
               $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_compile_definitions(
        libminizipstatic
        PRIVATE $<$<BOOL:${MSVC}>:_CRT_SECURE_NO_WARNINGS>
                $<$<BOOL:${HAVE___ATTR__VIS_HIDDEN}>:HAVE_HIDDEN>
                $<$<BOOL:${HAVE_UNISTD_H}>:HAVE_UNISTD_H=1>
        PUBLIC $<$<BOOL:${HAVE_OFF64_T}>:_LARGEFILE64_SOURCE=1>
                $<$<BOOL:${BZIP2_FOUND}>:HAVE_BZIP2=1>
                $<$<BOOL:NOT:${HAVE_FOPEN64}>:USE_FILE32API=1>)
    set_target_properties(
        libminizipstatic PROPERTIES EXPORT_NAME minizipstatic
                                    OUTPUT_NAME minizip${minizip_static_suffix})

    if(CYGWIN)
        set_target_properties(libminizipstatic PROPERTIES SUFFIX ".dll.a")
    endif(CYGWIN)

    target_link_libraries(libminizipstatic PUBLIC ZLIB::ZLIBSTATIC
        $<$<BOOL:${BZIP2_FOUND}>:BZip2::BZip2>)

    add_executable(minizipstatic ${MINIZIP_SRCS} ${MINIZIP_HDRS})
    set_target_properties(minizipstatic PROPERTIES EXPORT_NAME
                                                   minizip_static_executable)
    target_compile_definitions(
        minizipstatic PRIVATE $<$<BOOL:${MSVC}>:_CRT_SECURE_NO_WARNINGS>)
    target_link_libraries(minizipstatic PRIVATE MINIZIP::minizipstatic)
    add_executable(miniunzipstatic ${MINIUNZIP_SRCS} ${MINIUNZIP_HDRS})
    set_target_properties(miniunzipstatic
                          PROPERTIES EXPORT_NAME miniunzip_static_executable)
    target_compile_definitions(
        miniunzipstatic PRIVATE $<$<BOOL:${MSVC}>:_CRT_SECURE_NO_WARNINGS>)
    target_link_libraries(miniunzipstatic PRIVATE MINIZIP::minizipstatic)
endif(MINIZIP_BUILD_STATIC)

if(MINIZIP_INSTALL)
    if(MINIZIP_BUILD_SHARED)
        install(
            TARGETS libminizip minizip miniunzip
            COMPONENT Runtime
            EXPORT minizipSharedExport
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
        install(
            EXPORT minizipSharedExport
            FILE minizip-shared.cmake
            NAMESPACE MINIZIP::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/minizip)
        if(MINIZIP_INSTALL_COMPAT_DLL)
            install(
                FILES $<TARGET_FILE:libminizip>
                COMPONENT Runtime
                RENAME libminizip-${minizip_VERSION_MAJOR}.dll
                DESTINATION "${CMAKE_INSTALL_BINDIR}")
        endif(MINIZIP_INSTALL_COMPAT_DLL)

        if(MSVC)
            install(
                FILES $<TARGET_PDB_FILE:libminizip>
                COMPONENT Runtime
                DESTINATION ${CMAKE_INSTALL_BINDIR}
                CONFIGURATIONS Debug OR RelWithDebInfo
                OPTIONAL)
        endif(MSVC)
    endif(MINIZIP_BUILD_SHARED)

    if(MINIZIP_BUILD_STATIC)
        install(
            TARGETS libminizipstatic
            COMPONENT Development
            TARGETS minizipstatic miniunzipstatic
            COMPONENT Runtime
            EXPORT minizipStaticExport
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
        install(
            EXPORT minizipStaticExport
            FILE minizip-static.cmake
            NAMESPACE MINIZIP::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/minizip)
    endif(MINIZIP_BUILD_STATIC)

    configure_package_config_file(
        ${minizip_SOURCE_DIR}/minizipConfig.cmake.in
        ${minizip_BINARY_DIR}/minizipConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/minizip)
    write_basic_package_version_file(
        "${minizip_BINARY_DIR}/minizipConfigVersion.cmake"
        VERSION "${minizip_VERSION}"
        COMPATIBILITY AnyNewerVersion)
    install(FILES ${minizip_BINARY_DIR}/minizipConfig.cmake
                  ${minizip_BINARY_DIR}/minizipConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/minizip)
    install(
        FILES ${LIBMINIZIP_HDRS}
        COMPONENT Development
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
endif(MINIZIP_INSTALL)

if(MINIZIP_BUILD_TESTING)
    enable_testing()

    if(MINIZIP_BUILD_SHARED AND NOT ${CMAKE_SHARED_LIBRARY_SUFFIX} STREQUAL
                                ".dll")
        add_test(
            NAME minizip_prepare_shared_zip
            COMMAND ${CMAKE_COMMAND} -DCREATE_SHARED=ON -P
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_helper.cm
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_zipping_test_file_shared
            COMMAND minizip test_file_shared.zip test_file_shared.txt
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_prepare_shared_unzip
            COMMAND ${CMAKE_COMMAND} -DMOVE_SHARED=ON -P
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_helper.cm
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_miniunzipping_test_file_shared.zip
            COMMAND miniunzip test_file_shared.zip
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_compare_shared
            COMMAND ${CMAKE_COMMAND} -E compare_files test_file_shared.txt
                    test_file_shared.orig
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_clean_shared_zip
            COMMAND ${CMAKE_COMMAND} -DDELETE_SHARED=ON -P
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_helper.cm
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        set_tests_properties(minizip_prepare_shared_zip
                             PROPERTIES FIXTURES_SETUP prepare_shared)
        set_tests_properties(
            minizip_zipping_test_file_shared
            PROPERTIES FIXTURES_REQUIRED prepare_shared FIXTURES_SETUP
                       zip_shared)
        set_tests_properties(
            minizip_prepare_shared_unzip
            PROPERTIES FIXTURES_REQUIRED zip_shared FIXTURES_SETUP
                       prepare_unzip_shared)
        set_tests_properties(
            minizip_miniunzipping_test_file_shared.zip
            PROPERTIES FIXTURES_REQUIRED prepare_unzip_shared FIXTURES_SETUP
                       prepare_compare_shared)
        set_tests_properties(
            minizip_compare_shared
            PROPERTIES FIXTURES_REQUIRED prepare_compare_shared FIXTURES_SETUP
                       compared_shared)
        set_tests_properties(minizip_clean_shared_zip
                             PROPERTIES FIXTURES_CLEANUP compared_shared)
    endif(MINIZIP_BUILD_SHARED AND NOT ${CMAKE_SHARED_LIBRARY_SUFFIX} STREQUAL
                                   ".dll")

    if(MINIZIP_BUILD_STATIC)
        add_test(
            NAME minizip_prepare_static_zip
            COMMAND ${CMAKE_COMMAND} -DCREATE_STATIC=ON -P
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_helper.cm
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_zipping_test_file_static
            COMMAND minizipstatic test_file_static.zip test_file_static.txt
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_prepare_static_unzip
            COMMAND ${CMAKE_COMMAND} -DMOVE_STATIC=ON -P
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_helper.cm
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_miniunzipping_test_file_static.zip
            COMMAND miniunzipstatic test_file_static.zip
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_compare_static
            COMMAND ${CMAKE_COMMAND} -E compare_files test_file_static.txt
                    test_file_static.orig
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        add_test(
            NAME minizip_clean_static_zip
            COMMAND ${CMAKE_COMMAND} -DDELETE_STATIC=ON -P
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_helper.cm
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test)
        set_tests_properties(minizip_prepare_static_zip
                             PROPERTIES FIXTURES_SETUP prepare_static)
        set_tests_properties(
            minizip_zipping_test_file_static
            PROPERTIES FIXTURES_REQUIRED prepare_static FIXTURES_SETUP
                       zip_static)
        set_tests_properties(
            minizip_prepare_static_unzip
            PROPERTIES FIXTURES_REQUIRED zip_static FIXTURES_SETUP
                       prepare_unzip_static)
        set_tests_properties(
            minizip_miniunzipping_test_file_static.zip
            PROPERTIES FIXTURES_REQUIRED prepare_unzip_static FIXTURES_SETUP
                       prepare_compare_static)
        set_tests_properties(
            minizip_compare_static
            PROPERTIES FIXTURES_REQUIRED prepare_compare_static FIXTURES_SETUP
                       compared_static)
        set_tests_properties(minizip_clean_static_zip
                             PROPERTIES FIXTURES_CLEANUP compared_static)
    endif(MINIZIP_BUILD_STATIC)

    add_subdirectory(test)
endif(MINIZIP_BUILD_TESTING)
