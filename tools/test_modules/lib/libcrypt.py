#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# libc crypt () for the modes whose oracle it is: DES crypt, BSDi crypt and the yescrypt family. It
# is called through ctypes, so it needs no package on any python, and it is the routine the crypt
# module python 3.13 removed and perl's crypt () both reach.
#
# crypt_r () gets a crypt_data of its own on every call, so concurrent calls share no state. Where
# libc has only crypt (), whose result sits in a static buffer, a lock serialises the calls and the
# result is copied out before the lock is released.

import ctypes
import ctypes.util
import os
import threading

_LIB = ctypes.CDLL(ctypes.util.find_library("crypt"), use_errno=True)

# struct crypt_data is 32768 bytes in libxcrypt and 131232 in the libcrypt older glibc carried

_DATA_SIZE = 262144

_CRYPT_R = getattr(_LIB, "crypt_r", None)

if _CRYPT_R:
  _CRYPT_R.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
  _CRYPT_R.restype  = ctypes.c_char_p

_CRYPT = _LIB.crypt

_CRYPT.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_CRYPT.restype  = ctypes.c_char_p

_CRYPT_LOCK = threading.Lock()


def crypt(word: str, salt: str) -> str:
  if ("\0" in word) or ("\0" in salt): raise ValueError("embedded null character")

  word_b = word.encode("utf-8")
  salt_b = salt.encode("utf-8")

  if _CRYPT_R is None:
    with _CRYPT_LOCK:
      out = _CRYPT(word_b, salt_b)
      err = ctypes.get_errno()
  else:
    data = ctypes.create_string_buffer(_DATA_SIZE)
    out  = _CRYPT_R(word_b, salt_b, data)
    err  = ctypes.get_errno()

  if out is None: raise OSError(err, os.strerror(err))

  result = out.decode("utf-8")

  return result
