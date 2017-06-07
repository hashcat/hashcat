#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([hashcat], [3.3.0], [atom@hashcat.net])
AC_CONFIG_SRCDIR([src/tuningdb.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall subdir-objects])

#magic for conditional check in Makefile:
MK=''; AC_SUBST(MK)
SED=sed

# Checks for programs.
AM_PROG_AR
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL

# Checks for libraries.
LT_INIT([shared static])

app_cv_link_all_option="-Wl,--whole-archive"
app_cv_no_link_all_option="-Wl,--no-whole-archive"
app_cv_platform_type="Unix"

AC_CACHE_CHECK([type of operating system we're going to host on],
               [app_cv_os_type],
[case $host in
  *-*-aix*)
    app_cv_os_type="AIX"
    ;;
  *-*-irix*)
    app_cv_os_type="IRIX"
    ;;
  *-*-cygwin*)
    app_cv_os_type="Cygwin"
    ;;
  *-*-darwin*)
    app_cv_link_all_option="-Wl,-all_load"
    app_cv_no_link_all_option="-Wl,-noall_load"
    app_cv_os_type="Darwin"
    ;;
  *-*-minix*)
    app_cv_link_all_option="-Wl,-all_load"
    app_cv_no_link_all_option="-Wl,-noall_load"
    app_cv_os_type="Minix"
    ;;
  *-*-freebsd*)
    app_cv_os_type="FreeBSD"
    ;;
  *-*-kfreebsd-gnu)
    app_cv_os_type="GNU/kFreeBSD"
    ;;
  *-*-openbsd*)
    app_cv_os_type="OpenBSD"
    ;;
  *-*-netbsd*)
    app_cv_os_type="NetBSD"
    ;;
  *-*-dragonfly*)
    app_cv_os_type="DragonFly"
    ;;
  *-*-hpux*)
    app_cv_os_type="HP-UX"
    ;;
  *-*-interix*)
    app_cv_os_type="Interix"
    ;;
  *-*-linux*)
    app_cv_os_type="Linux"
    ;;
  *-*-gnu*)
    app_cv_os_type="GNU"
    ;;
  *-*-solaris*)
    app_cv_link_all_option="-Wl,-z,allextract"
    app_cv_no_link_all_option="-Wl,-z,defaultextract"
    app_cv_os_type="SunOS"
    ;;
  *-*-auroraux*)
    app_cv_link_all_option="-Wl,-z,allextract"
    app_cv_link_all_option="-Wl,-z,defaultextract"
    app_cv_os_type="AuroraUX"
    ;;
  *-*-win32*)
    app_cv_os_type="Win32"
    app_cv_platform_type="Win32"
    ;;
  *-*-mingw*)
    app_cv_os_type="MingW"
    app_cv_platform_type="Win32"
    ;;
  *-*-haiku*)
    app_cv_os_type="Haiku"
    ;;
  *-unknown-eabi*)
    app_cv_os_type="Freestanding"
    ;;
  *-unknown-elf*)
    app_cv_os_type="Freestanding"
    ;;
  *)
    app_cv_link_all_option=""
    app_cv_no_link_all_option=""
    app_cv_os_type="Unknown"
    app_cv_platform_type="Unknown"
    ;;
esac])

AC_CACHE_CHECK([type of operating system we're going to target],
               [app_cv_target_os_type],
[case $target in
  *-*-aix*)
    app_cv_target_os_type="AIX" ;;
  *-*-irix*)
    app_cv_target_os_type="IRIX" ;;
  *-*-cygwin*)
    app_cv_target_os_type="Cygwin" ;;
  *-*-darwin*)
    app_cv_target_os_type="Darwin" ;;
  *-*-minix*)
    app_cv_target_os_type="Minix" ;;
  *-*-freebsd*)
    app_cv_target_os_type="FreeBSD" ;;
  *-*-kfreebsd-gnu)
    app_cv_target_os_type="GNU/kFreeBSD" ;;
  *-*-openbsd*)
    app_cv_target_os_type="OpenBSD" ;;
  *-*-netbsd*)
    app_cv_target_os_type="NetBSD" ;;
  *-*-dragonfly*)
    app_cv_target_os_type="DragonFly" ;;
  *-*-hpux*)
    app_cv_target_os_type="HP-UX" ;;
  *-*-interix*)
    app_cv_target_os_type="Interix" ;;
  *-*-linux*)
    app_cv_target_os_type="Linux" ;;
  *-*-gnu*)
    app_cv_target_os_type="GNU" ;;
  *-*-solaris*)
    app_cv_target_os_type="SunOS" ;;
  *-*-auroraux*)
    app_cv_target_os_type="AuroraUX" ;;
  *-*-win32*)
    app_cv_target_os_type="Win32" ;;
  *-*-mingw*)
    app_cv_target_os_type="MingW" ;;
  *-*-haiku*)
    app_cv_target_os_type="Haiku" ;;
  *-*-rtems*)
    app_cv_target_os_type="RTEMS" ;;
  *-*-nacl*)
    app_cv_target_os_type="NativeClient" ;;
  *-unknown-eabi*)
    app_cv_target_os_type="Freestanding" ;;
  *)
    app_cv_target_os_type="Unknown" ;;
esac])

if test "$app_cv_os_type" = "MingW" ; then
  AC_CHECK_HEADERS([windows.h psapi.h])
  AC_CHECK_LIB(psapi, [main], [LIBPSAPI=-lpsapi])
  AC_SUBST(LIBPSAPI)
  #AC_CHECK_LIB(shlwapi, PathIsDirectory, [LIBSHLWAPI=-lshlwapi])
  #AC_SUBST(LIBSHLWAPI)
fi

# Checks for libraries.
# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])

# debug
AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug],[Compile the debug version (default: disabled)]),
	[enable_debug=$enableval],
	[enable_debug=no])
AM_CONDITIONAL([DEBUG], [test $enable_debug = "yes"])
AM_COND_IF(DEBUG,
    AC_DEFINE(DEBUG, 1, [Define to 0 if this is a release build]),
    AC_DEFINE(DEBUG, 0, [Define to 1 or higher if this is a debug build]))
if test "x$enable_debug" = "xyes"; then
  changequote({,})
  CFLAGS=`echo "$CFLAGS" | $SED -e 's/-O[0-9s]*//g'`
  CXXFLAGS=`echo "$CXXFLAGS" | $SED -e 's/-O[0-9s]*//g'`
  changequote([,])
  dnl add -O0 only if GCC or ICC is used
  if test "$GCC" = "yes" || test "$ICC" = "yes"; then
    CFLAGS="$CFLAGS -O0"
    CXXFLAGS="$CXXFLAGS -O0"
  fi
else
  changequote({,})
  CFLAGS=`echo "$CFLAGS" | $SED -e 's/-g//g'`
  CXXFLAGS=`echo "$CXXFLAGS" | $SED -e 's/-g//g'`
  changequote([,])
fi

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h mach/mach.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/time.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getcwd gettimeofday memmove memset mkdir putenv realpath rmdir select strchr strdup strerror strrchr strstr])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/libhashcat.pc
                 ])
AC_OUTPUT
