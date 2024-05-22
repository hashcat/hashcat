project(
  'hashcat',
  'c',
  'cpp',
  version: '6.3.1',
  default_options: ['c_std=gnu11', 'cpp_std=c++11', 'warning_level=1'],
  meson_version: '>=0.49.0',
)

cc = meson.get_compiler('c')

if cc.links('#include <iconv.h>\nint main(){iconv_open("", "");}')
  iconv_dep = dependency('', required: false)
else
  iconv_dep = cc.find_library('iconv')
endif

threads_dep = dependency('threads')

deps = [
  iconv_dep,
  threads_dep,
  dependency('OpenCL-Headers'),
  dependency('minizip'),
  dependency('libxxhash'),
  dependency('zlib'),
]

if host_machine.system() != 'windows'
  if meson.version().version_compare('>=0.62')
    deps += dependency('dl')
  else
    deps += cc.find_library('dl')
  endif
endif

if host_machine.system() == 'windows'
  deps += cc.find_library('psapi')
  deps += cc.find_library('ws2_32')
  if meson.is_cross_build()
    deps += cc.find_library('ssp')
  endif
elif host_machine.system() == 'darwin'
  deps += dependency('appleframeworks', modules: ['CoreFoundation', 'Foundation', 'IOKit', 'Metal'])
else
  deps += cc.find_library('m')
endif

lzma = static_library(
  'lzma',
  'deps/LZMA-SDK/C/7zAlloc.c',
  'deps/LZMA-SDK/C/7zArcIn.c',
  'deps/LZMA-SDK/C/7zBuf.c',
  'deps/LZMA-SDK/C/7zBuf2.c',
  'deps/LZMA-SDK/C/7zCrc.c',
  'deps/LZMA-SDK/C/7zCrcOpt.c',
  'deps/LZMA-SDK/C/7zDec.c',
  'deps/LZMA-SDK/C/7zFile.c',
  'deps/LZMA-SDK/C/7zStream.c',
  'deps/LZMA-SDK/C/Aes.c',
  'deps/LZMA-SDK/C/AesOpt.c',
  'deps/LZMA-SDK/C/Alloc.c',
  'deps/LZMA-SDK/C/Bcj2.c',
  'deps/LZMA-SDK/C/Bcj2Enc.c',
  'deps/LZMA-SDK/C/Bra.c',
  'deps/LZMA-SDK/C/Bra86.c',
  'deps/LZMA-SDK/C/BraIA64.c',
  'deps/LZMA-SDK/C/CpuArch.c',
  'deps/LZMA-SDK/C/Delta.c',
  'deps/LZMA-SDK/C/DllSecur.c',
  'deps/LZMA-SDK/C/LzFind.c',
  'deps/LZMA-SDK/C/LzFindMt.c',
  'deps/LZMA-SDK/C/Lzma2Dec.c',
  'deps/LZMA-SDK/C/Lzma2DecMt.c',
  'deps/LZMA-SDK/C/Lzma2Enc.c',
  'deps/LZMA-SDK/C/Lzma86Dec.c',
  'deps/LZMA-SDK/C/Lzma86Enc.c',
  'deps/LZMA-SDK/C/LzmaDec.c',
  'deps/LZMA-SDK/C/LzmaEnc.c',
  'deps/LZMA-SDK/C/LzmaLib.c',
  'deps/LZMA-SDK/C/MtCoder.c',
  'deps/LZMA-SDK/C/MtDec.c',
  'deps/LZMA-SDK/C/Ppmd7.c',
  'deps/LZMA-SDK/C/Ppmd7Dec.c',
  'deps/LZMA-SDK/C/Ppmd7Enc.c',
  'deps/LZMA-SDK/C/Sha256.c',
  'deps/LZMA-SDK/C/Sha256Opt.c',
  'deps/LZMA-SDK/C/Sort.c',
  'deps/LZMA-SDK/C/Threads.c',
  'deps/LZMA-SDK/C/Xz.c',
  'deps/LZMA-SDK/C/XzCrc64.c',
  'deps/LZMA-SDK/C/XzCrc64Opt.c',
  'deps/LZMA-SDK/C/XzDec.c',
  'deps/LZMA-SDK/C/XzEnc.c',
  'deps/LZMA-SDK/C/XzIn.c',
  dependencies: threads_dep,
)

lzma_inc = include_directories('deps/LZMA-SDK/C')
lzma_dep = declare_dependency(
  include_directories: lzma_inc,
  link_with: lzma,
)

deps += lzma_dep

if get_option('unrar') and host_machine.system() != 'cygwin'
  unrar = static_library(
    'unrar',
    'deps/unrar/archive.cpp',
    'deps/unrar/arcread.cpp',
    'deps/unrar/blake2s.cpp',
    'deps/unrar/cmddata.cpp',
    'deps/unrar/consio.cpp',
    'deps/unrar/crc.cpp',
    'deps/unrar/crypt.cpp',
    'deps/unrar/encname.cpp',
    'deps/unrar/errhnd.cpp',
    'deps/unrar/extinfo.cpp',
    'deps/unrar/extract.cpp',
    'deps/unrar/filcreat.cpp',
    'deps/unrar/file.cpp',
    'deps/unrar/filefn.cpp',
    'deps/unrar/filestr.cpp',
    'deps/unrar/find.cpp',
    'deps/unrar/getbits.cpp',
    'deps/unrar/global.cpp',
    'deps/unrar/hash.cpp',
    'deps/unrar/hc_decompress_rar.cpp',
    'deps/unrar/headers.cpp',
    'deps/unrar/isnt.cpp',
    'deps/unrar/list.cpp',
    'deps/unrar/match.cpp',
    'deps/unrar/options.cpp',
    'deps/unrar/pathfn.cpp',
    'deps/unrar/qopen.cpp',
    'deps/unrar/rarvm.cpp',
    'deps/unrar/rawread.cpp',
    'deps/unrar/rdwrfn.cpp',
    'deps/unrar/recvol.cpp',
    'deps/unrar/resource.cpp',
    'deps/unrar/rijndael.cpp',
    'deps/unrar/rs.cpp',
    'deps/unrar/rs16.cpp',
    'deps/unrar/scantree.cpp',
    'deps/unrar/secpassword.cpp',
    'deps/unrar/sha1.cpp',
    'deps/unrar/sha256.cpp',
    'deps/unrar/smallfn.cpp',
    'deps/unrar/strfn.cpp',
    'deps/unrar/strlist.cpp',
    'deps/unrar/system.cpp',
    'deps/unrar/threadpool.cpp',
    'deps/unrar/timefn.cpp',
    'deps/unrar/ui.cpp',
    'deps/unrar/unicode.cpp',
    'deps/unrar/unpack.cpp',
    'deps/unrar/volume.cpp',
  )

  unrar_inc = include_directories('deps/unrar')
  unrar_dep = declare_dependency(
    include_directories: unrar_inc,
    link_with: unrar,
  )

  deps += unrar_dep
  if host_machine.system() == 'windows'
    deps += cc.find_library('powrprof')
    deps += cc.find_library('wbemuuid')
  endif
else
  unrar_dep = dependency('', required: false)
endif

incdirs = include_directories('include', 'OpenCL')

subdir('src')
subdir('modules')

install_data(
  'hashcat.hcstat2',
  install_dir: get_option('libdir') / meson.project_name(),
)

install_subdir(
  'OpenCL',
  install_dir: get_option('libdir') / meson.project_name(),
)

install_subdir(
  'tunings',
  install_dir: get_option('libdir') / meson.project_name(),
)

install_subdir(
  'charsets',
  install_dir: get_option('datadir') / 'doc' / meson.project_name(),
)

install_subdir(
  'docs',
  install_dir: get_option('datadir') / 'doc' / meson.project_name(),
)

install_subdir(
  'layouts',
  install_dir: get_option('datadir') / 'doc' / meson.project_name(),
)

install_subdir(
  'masks',
  install_dir: get_option('datadir') / 'doc' / meson.project_name(),
)

install_subdir(
  'rules',
  install_dir: get_option('datadir') / 'doc' / meson.project_name(),
)

install_data(
  'example0.sh',
  'example400.sh',
  'example500.sh',
  'example.dict',
  install_dir: get_option('datadir') / 'doc' / meson.project_name(),
)

executable(
  'hashcat',
  'src/main.c',
  c_args: ['-DCOMPTIME=0', '-DVERSION_TAG="@0@"'.format(meson.project_version())],
  dependencies: libhashcat_dep,
  pie: true,
  install: true,
)
