libhashcat_srcs = files(
  'affinity.c',
  'autotune.c',
  'backend.c',
  'benchmark.c',
  'bitmap.c',
  'bitops.c',
  'combinator.c',
  'common.c',
  'convert.c',
  'cpt.c',
  'cpu_crc32.c',
  'debugfile.c',
  'dictstat.c',
  'dispatch.c',
  'dynloader.c',
  'emu_general.c',
  'emu_inc_bignum_operations.c',
  'emu_inc_cipher_aes.c',
  'emu_inc_cipher_camellia.c',
  'emu_inc_cipher_des.c',
  'emu_inc_cipher_kuznyechik.c',
  'emu_inc_cipher_serpent.c',
  'emu_inc_cipher_twofish.c',
  'emu_inc_common.c',
  'emu_inc_ecc_secp256k1.c',
  'emu_inc_hash_base58.c',
  'emu_inc_hash_md4.c',
  'emu_inc_hash_md5.c',
  'emu_inc_hash_ripemd160.c',
  'emu_inc_hash_sha1.c',
  'emu_inc_hash_sha224.c',
  'emu_inc_hash_sha256.c',
  'emu_inc_hash_sha384.c',
  'emu_inc_hash_sha512.c',
  'emu_inc_hash_streebog256.c',
  'emu_inc_hash_streebog512.c',
  'emu_inc_hash_whirlpool.c',
  'emu_inc_platform.c',
  'emu_inc_rp.c',
  'emu_inc_rp_optimized.c',
  'emu_inc_scalar.c',
  'emu_inc_simd.c',
  'event.c',
  'ext_ADL.c',
  'ext_OpenCL.c',
  'ext_cuda.c',
  'ext_hip.c',
  'ext_hiprtc.c',
  'ext_iokit.c',
  'ext_lzma.c',
  'ext_nvapi.c',
  'ext_nvml.c',
  'ext_nvrtc.c',
  'ext_sysfs_amdgpu.c',
  'ext_sysfs_cpu.c',
  'filehandling.c',
  'folder.c',
  'hashcat.c',
  'hashes.c',
  'hlfmt.c',
  'hwmon.c',
  'induct.c',
  'interface.c',
  'keyboard_layout.c',
  'locking.c',
  'logfile.c',
  'loopback.c',
  'memory.c',
  'monitor.c',
  'mpsp.c',
  'outfile.c',
  'outfile_check.c',
  'pidfile.c',
  'potfile.c',
  'restore.c',
  'rp.c',
  'rp_cpu.c',
  'selftest.c',
  'shared.c',
  'slow_candidates.c',
  'status.c',
  'stdout.c',
  'straight.c',
  'terminal.c',
  'thread.c',
  'timer.c',
  'tuningdb.c',
  'usage.c',
  'user_options.c',
  'wordlist.c',
)

if host_machine.system() == 'darwin'
  add_languages('objc')
  libhashcat_srcs += files('ext_metal.m')
endif

hashcat_args = []
if get_option('brain')
  hashcat_args += '-DWITH_BRAIN'
  libhashcat_srcs += 'brain.c'
endif

if get_option('cubin')
  hashcat_args += '-DWITH_CUBIN'
endif

if host_machine.system() in ['cygwin', 'darwin', 'linux', 'windows']
  hashcat_args += '-DWITH_HWMON'
endif

libhashcat = library(
  'hashcat',
  libhashcat_srcs,
  c_args: hashcat_args,
  include_directories: incdirs,
  version: meson.project_version(),
  dependencies: deps,
  install: true,
)

libhashcat_dep = declare_dependency(
  dependencies: deps,
  include_directories: incdirs,
  link_with: libhashcat,
)
