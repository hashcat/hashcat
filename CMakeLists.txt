CMAKE_MINIMUM_REQUIRED(VERSION 3.5)
PROJECT(hashcat)

set(CMAKE_USE_RELATIVE_PATHS TRUE)

set(PACKAGE_NAME "hashcat" CACHE STRING "Program name")
set(PACKAGE_VERSION ${VERSION})
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")

FIND_PACKAGE(Git)
if(GIT_FOUND)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --tags --dirty --long
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE VERSION_FROM_GIT
    RESULT_VARIABLE GIT_RESULT
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT GIT_RESULT EQUAL 0)
    message(WARNING "git returned error ${VERSION_FROM_GIT}")
    set(VERSION_FROM_GIT "unknown")
  endif()
else(GIT_FOUND)
  set(VERSION_FROM_GIT "v3.10")
endif(GIT_FOUND)


string(REGEX MATCH "^v[0-9]+(\\.[0-9]+)+" VERSION ${VERSION_FROM_GIT})
string(REGEX MATCHALL "[0-9]+" PARSED_VER ${VERSION})

list(LENGTH PARSED_VER PARSED_VER_LEN)
if(PARSED_VER_LEN GREATER 0)
  list(GET PARSED_VER 0 VERSION_MAJOR)
else()
  set(VERSION_MAJOR 0)
endif()
if(PARSED_VER_LEN GREATER 1)
  list(GET PARSED_VER 1 VERSION_MINOR)
else()
  set(VERSION_MINOR 0)
endif()
if(PARSED_VER_LEN GREATER 2)
  list(GET PARSED_VER 2 VERSION_PATCH)
else()
  set(VERSION_PATCH 0)
endif()
if(PARSED_VER_LEN GREATER 3)
  list(GET PARSED_VER 3 VERSION_TWEAK)
else()
  set(VERSION_TWEAK 0)
endif()

set(VERSION_BIN "${VERSION_MAJOR}${VERSION_MINOR}${VERSION_PATCH}")
message(STATUS "hashcat version: ${VERSION}")
message(STATUS "hashcat bin version: ${VERSION_BIN}")

if(GIT_FOUND)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%ct
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE COMPTIME
    RESULT_VARIABLE GIT_RESULT
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT GIT_RESULT EQUAL 0)
    set(COMPTIME "0000000000")
  endif()

  execute_process(
    COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%D
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE VERSION_EXPORT
    RESULT_VARIABLE GIT_RESULT
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT GIT_RESULT EQUAL 0)
    set(VERSION_EXPORT "HEAD -> master")
  endif()
else(GIT_FOUND)
  set(COMPTIME "0000000000")
  set(VERSION_EXPORT "HEAD -> master")
endif(GIT_FOUND)
set(VERSION_TAG "${VERSION_EXPORT} ${VERSION_FROM_GIT}")
message(STATUS "version tag: ${VERSION_TAG}")

set(deps_Dir "${CMAKE_CURRENT_SOURCE_DIR}/deps/")
set(OPENCL_HEADERS_KHRONOS "${deps_Dir}/OpenCL-Headers")

FIND_PACKAGE(OpenCL)
if(OpenCL_FOUND)
  #link_libraries(${OpenCL_LIBRARY})
else()
  message(STATUS "Using deps/OpenCL-Headers")
  set(OpenCL_INCLUDE_DIR ${OPENCL_HEADERS_KHRONOS})
endif()
include_directories(hashcat ${OpenCL_INCLUDE_DIR})

##
## Compiler flags
##

# if(DEBUG)
  # set(CFLAGS "${CFLAGS} -O2")
# else(DEBUG)
  # set(CFLAGS "${CFLAGS} -DDEBUG -g -ggdb")
  # if(DEBUG == 2)
    # set(CFLAGS "${CFLAGS} -fsanitize=address -fno-omit-frame-pointer")
  # endif()
# endif(DEBUG)

##
## Native compilation target
##


#set(BINARY_NATIVE, PROG_NAME)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darvin")
set(MACOS TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
set(LINUX TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
set(FREEBSD TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
set(WINDOWS TRUE)
endif()

if(MACOS)
  set(MACOSX_DEPLOYMENT_TARGET 10.9)
  set(POSIX TRUE)
  set(CMAKE_EXE_LINKER_FLAGS "-lpthread ${CMAKE_EXE_LINKER_FLAGS}")
endif() # darwin

if(LINUX)
  set(POSIX TRUE)
  set(CMAKE_EXE_LINKER_FLAGS "-lpthread -ldl ${CMAKE_EXE_LINKER_FLAGS}")
endif() # linux

if(FREEBSD)
  set(POSIX TRUE)
  set(CMAKE_EXE_LINKER_FLAGS "-lpthread ${LDFLAGS}")
endif() # freebsd

if(WINDOWS OR MINGW OR LINUX)
  set(WITH_HWMON TRUE)
endif()

if(MINGW)
  # force MinGW-w64 in 32bit mode
  #add_compile_options(hashcat PUBLIC "-m32")
  #set_target_properties(hashcat PROPERTIES COMPILE_FLAGS "-m32")
  #set_target_properties(hashcat PROPERTIES LINK_FLAGS "-m32 -Wl,--enable-stdcall-fixup")
  #set_target_properties(hashcat PROPERTIES RC_FLAGS "--target=pe-i386 --output-format=coff")
endif(MINGW)

if(MSVC)
  #add_compile_options("/GL /Qvec-report:1 /Qpar-report:1") # it causes compilation error due flag conflict
  #set_target_properties(hashcat PROPERTIES COMPILE_FLAGS "/GL /Qvec-report:1 /Qpar-report:1")
  #set_target_properties(hashcat PROPERTIES LINK_FLAGS "/LTCG")
endif(MSVC)


if(MSVC)
  set(nixShims4Windows_DIR "${deps_Dir}/nixShims4Windows")
  include("${nixShims4Windows_DIR}/CMakeLists.txt")
  link_libraries(${shimLibs})
  set(WITH_HWMON TRUE)
endif(MSVC)


set(Include_dir "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(Source_dir "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(OpenCL_Proj_DIR "${CMAKE_CURRENT_SOURCE_DIR}/OpenCL")
set(masks_DIR "${CMAKE_CURRENT_SOURCE_DIR}/masks")
set(rules_DIR "${CMAKE_CURRENT_SOURCE_DIR}/rules")
set(charsets_DIR "${CMAKE_CURRENT_SOURCE_DIR}/charsets")
set(resource_DIR "${CMAKE_CURRENT_SOURCE_DIR}/res")
set(CMake_Misc_Dir "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories(${Include_dir} ${OpenCL_Proj_DIR} ${shimIncludeDirs})
file(GLOB_RECURSE SRCFILES "${Source_dir}/*.c")

if(MSVC)
  #making resource file
  set(rc_script "${resource_DIR}/hashcat.rc")
  set(rc_script_proto "${CMake_Misc_Dir}/hashcat.rc.in")
  set(license_file "${CMAKE_CURRENT_SOURCE_DIR}/docs/license.txt")
  file(READ ${license_file} LICENSE_TEXT)
  string(REPLACE "\"" "\"\"" LICENSE_TEXT ${LICENSE_TEXT})
  string(REPLACE "\r\n" "\n" LICENSE_TEXT ${LICENSE_TEXT})
  string(REPLACE "\n" "\\r\\n" LICENSE_TEXT ${LICENSE_TEXT})
  message(STATUS "generating resources: ${rc_script_proto} -> ${rc_script}")
  configure_file(${rc_script_proto} ${rc_script})
  file(GLOB_RECURSE resource_files "${resource_DIR}/*.rc" "${resource_DIR}/*.ico")
endif(MSVC)

if(MSVC_IDE)
   file(GLOB_RECURSE HDRFILES "${Include_dir}/*.h")
   file(GLOB_RECURSE OpenCL_Kernels "${OpenCL_Proj_DIR}/*.cl")
   file(GLOB_RECURSE masks_files "${masks_DIR}/*.hcmask")
   file(GLOB_RECURSE rules_files "${rules_DIR}/*.rule")
endif()

add_executable(hashcat "${shimSources}" "${SRCFILES}" "${HDRFILES}" "${OpenCL_Kernels}" "${masks_files}" "${rules_files}" "${resource_files}")

if(MSVC_IDE)
   source_group("misc\\OpenCL" FILES  ${OpenCL_Kernels})
   source_group("misc\\masks" FILES  ${masks_files})
   source_group("misc\\rules" FILES  ${rules_files})
   source_group("res" FILES  ${resource_files})
   source_group("Header Files\\cpu" REGULAR_EXPRESSION "cpu-[a-zA-Z0-9]+\.h")
   source_group("Header Files\\hwmon" REGULAR_EXPRESSION "hwmon/[a-zA-Z0-9_-]+\.h")
   source_group("Source Files\\cpu" REGULAR_EXPRESSION "cpu-[a-zA-Z0-9]+\.c")
   source_group("Source Files\\hwmon" REGULAR_EXPRESSION "hwmon/[a-zA-Z0-9_-]+\.c")
endif()

if(MSVC)
  set_source_files_properties(${shimSources} ${SRCFILES} PROPERTIES LANGUAGE CXX)
else(MSVC)
  #set_source_files_properties(${shimSources} ${SRCFILES} PROPERTIES LANGUAGE CXX)
endif(MSVC)

#target_compile_features(hashcat PUBLIC cxx_decltype_auto)


# config.h
set(CONFIG_FILENAME "config.h")
set(CONFIG_FILE "${Include_dir}/${CONFIG_FILENAME}")
mark_as_advanced(CONFIG_FILE)
set(CONFIG_FILE_PROTO "${CMake_Misc_Dir}/${CONFIG_FILENAME}.in")

if(LINUX)
  set(INSTALL_PREFIX "/usr/local")
  set(INSTALL_FOLDER "${INSTALL_PREFIX}/bin" CACHE PATH "INSTALL_FOLDER")
  set(DOCUMENT_FOLDER "${INSTALL_PREFIX}/share/doc/${PROG_NAME}" CACHE PATH "DOCUMENT_FOLDER")
  set(SHARED_FOLDER "${INSTALL_PREFIX}/share/${PROG_NAME}" CACHE PATH "SHARED_FOLDER")
endif()


set(HASHCAT_HCSTAT_DEFAULT_FILENAME "${PACKAGE_NAME}.hcstat" CACHE STRING "Stat file name" FORCE) #SP_HCSTAT
set(HASHCAT_TUNING_DB_FILENAME "${PACKAGE_NAME}.hctune" CACHE STRING "Tuning db file name" FORCE) #TUNING_DB_FILE
set(HASHCAT_LOOPBACK_FILENAME "${PACKAGE_NAME}.loopback" CACHE STRING "Loopback file" FORCE) #LOOPBACK_FILE
set(HASHCAT_DICTSTAT_FILENAME "${PACKAGE_NAME}.dictstat" CACHE STRING "Dicstat file" FORCE) #DICTSTAT_FILENAME
set(HASHCAT_POTFILE_FILENAME "${PACKAGE_NAME}.pot" CACHE STRING "Loopback file" FORCE) #POTFILE_FILENAME

set(HASHCAT_INDUCT_DIR "induct" CACHE STRING "Induct dir") #INDUCT_DIR
set(HASHCAT_OUTFILES_DIR "outfiles" CACHE STRING "Output files dir") #OUTFILES_DIR
set(HASHCAT_SESSIONS_DIR "sessions" CACHE STRING "Output files dir") #SESSIONS_FOLDER
set(HASHCAT_PROFILE_DIR ".hashcat" CACHE STRING "Output files dir") #DOT_HASHCAT


set(HASHCAT_ETC_MAX 60*60*24*365*10 CACHE NUMBER "ETC max") #ETC_MAX
set(HASHCAT_DEVICES_MAX 128 CACHE INTEGER "Maximum number of OpenCL devices HC is able to use. It determines the sizes of arrays in structs. Reduce this to reduce memory footprint.")
set(HASHCAT_CL_PLATFORMS_MAX 16 CACHE INTEGER "devices max") #CL_PLATFORMS_MAX
set(HASHCAT_BLOCK_SIZE 64 CACHE INTEGER "BLOCK_SIZE") #BLOCK_SIZE
set(HASHCAT_CHARSIZ 0x100 CACHE INTEGER "CHARSIZ") #CHARSIZ
set(HASHCAT_EXEC_CACHE 128 CACHE INTEGER "EXEC_CACHE") #EXEC_CACHE
set(HASHCAT_SPEED_CACHE 128 CACHE INTEGER "SPEED_CACHE") #SPEED_CACHE
set(HASHCAT_SPEED_MAXAGE 4096 CACHE INTEGER "SPEED_MAXAGE") #SPEED_MAXAGE
# general large space buffer size in case the size is unknown at compile-time
set(HASHCAT_HCBUFSIZ 0x50000 CACHE INTEGER "SPEED_MAXAGE") #HCBUFSIZ
set(HASHCAT_EXPECTED_ITERATIONS_COUNT 0x50000 CACHE INTEGER "EXPECTED_ITERATIONS") #EXPECTED_ITERATIONS
set(HASHCAT_CPT_BUF 0x20000 CACHE INTEGER "CPT_BUF") #CPT_BUF
set(HASHCAT_MAX_CUT_TRIES 4 CACHE INTEGER "MAX_CUT_TRIES") #MAX_CUT_TRIES
set(HASHCAT_MAX_DICTSTAT 10000 CACHE INTEGER "MAX_DICTSTAT") #MAX_DICTSTAT

set(HASHCAT_VERIFIER_CNT 1 CACHE INTEGER "VERIFIER_CNT") #VERIFIER_CNT
set(HASHCAT_STEPS_CNT 10 CACHE INTEGER "STEPS_CNT") #STEPS_CNT

set(HASHCAT_RULES_MAX 256 CACHE INTEGER "RULES_MAX") #RULES_MAX
set(HASHCAT_PW_MIN 0 CACHE INTEGER "PW_MIN") #PW_MIN
set(HASHCAT_PW_MAX 54 CACHE INTEGER "PW_MAX") #PW_MAX
set(HASHCAT_SP_PW_MIN 2 CACHE INTEGER "PW_MAX") #PW_MAX
set(HASHCAT_SP_PW_MAX 64 CACHE INTEGER "PW_MAX") #PW_MAX

set(HASHCAT_PW_DICTMAX 31 CACHE INTEGER "PW_DICTMAX") #PW_DICTMAX
set(HASHCAT_PARAMCNT 64 CACHE INTEGER "PARAMCNT") #PARAMCNT
set(HASHCAT_INFOSZ CHARSIZ CACHE INTEGER "INFOSZ") #INFOSZ

set(WITH_HWMON ${WITH_HWMON} CACHE BOOL "Enable hardware monitoring to preserve hardware from overheating")

mark_as_advanced(
  HASHCAT_HCSTAT_DEFAULT_FILENAME
  HASHCAT_TUNING_DB_FILENAME
  HASHCAT_LOOPBACK_FILENAME
  HASHCAT_DICTSTAT_FILENAME
  HASHCAT_POTFILE_FILENAME

  HASHCAT_INDUCT_DIR
  HASHCAT_OUTFILES_DIR
  HASHCAT_PROFILE_DIR
  HASHCAT_SESSIONS_DIR

  HASHCAT_ETC_MAX
  HASHCAT_DEVICES_MAX
  HASHCAT_CL_PLATFORMS_MAX

  HASHCAT_BLOCK_SIZE
  HASHCAT_CHARSIZ
  HASHCAT_EXEC_CACHE
  HASHCAT_SPEED_CACHE
  HASHCAT_SPEED_MAXAGE
  HASHCAT_HCBUFSIZ
  HASHCAT_EXPECTED_ITERATIONS_COUNT
  HASHCAT_CPT_BUF
  HASHCAT_MAX_CUT_TRIES
  HASHCAT_MAX_DICTSTAT

  HASHCAT_STEPS_CNT
  HASHCAT_VERIFIER_CNT

  HASHCAT_RULES_MAX
  HASHCAT_PW_MIN
  HASHCAT_PW_MAX
  HASHCAT_SP_PW_MIN
  HASHCAT_SP_PW_MAX
  HASHCAT_PW_DICTMAX
  HASHCAT_PARAMCNT
  HASHCAT_INFOSZ
)

set(_POSIX ${POSIX})
message(STATUS "generating config: ${CONFIG_FILE_PROTO} -> ${CONFIG_FILE}")
configure_file(${CONFIG_FILE_PROTO} ${CONFIG_FILE})
