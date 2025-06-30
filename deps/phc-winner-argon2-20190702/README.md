# Argon2

[![Build Status](https://travis-ci.org/P-H-C/phc-winner-argon2.svg?branch=master)](https://travis-ci.org/P-H-C/phc-winner-argon2)
[![Build status](https://ci.appveyor.com/api/projects/status/8nfwuwq55sgfkele?svg=true)](https://ci.appveyor.com/project/P-H-C/phc-winner-argon2)
[![codecov.io](https://codecov.io/github/P-H-C/phc-winner-argon2/coverage.svg?branch=master)](https://codecov.io/github/P-H-C/phc-winner-argon2?branch=master)

This is the reference C implementation of Argon2, the password-hashing
function that won the [Password Hashing Competition
(PHC)](https://password-hashing.net).

Argon2 is a password-hashing function that summarizes the state of the
art in the design of memory-hard functions and can be used to hash
passwords for credential storage, key derivation, or other applications.

It has a simple design aimed at the highest memory filling rate and
effective use of multiple computing units, while still providing defense
against tradeoff attacks (by exploiting the cache and memory organization
of the recent processors).

Argon2 has three variants: Argon2i, Argon2d, and Argon2id. Argon2d is faster
and uses data-depending memory access, which makes it highly resistant
against GPU cracking attacks and suitable for applications with no threats
from side-channel timing attacks (eg. cryptocurrencies). Argon2i instead
uses data-independent memory access, which is preferred for password
hashing and password-based key derivation, but it is slower as it makes
more passes over the memory to protect from tradeoff attacks. Argon2id is a
hybrid of Argon2i and Argon2d, using a combination of data-depending and
data-independent memory accesses, which gives some of Argon2i's resistance to
side-channel cache timing attacks and much of Argon2d's resistance to GPU
cracking attacks.

Argon2i, Argon2d, and Argon2id are parametrized by:

* A **time** cost, which defines the amount of computation realized and
  therefore the execution time, given in number of iterations
* A **memory** cost, which defines the memory usage, given in kibibytes
* A **parallelism** degree, which defines the number of parallel threads

The [Argon2 document](argon2-specs.pdf) gives detailed specs and design
rationale.

Please report bugs as issues on this repository.

## Usage

`make` builds the executable `argon2`, the static library `libargon2.a`,
and the shared library `libargon2.so` (or `libargon2.dylib` on OSX).
Make sure to run `make test` to verify that your build produces valid
results. `make install PREFIX=/usr` installs it to your system.

### Command-line utility

`argon2` is a command-line utility to test specific Argon2 instances
on your system. To show usage instructions, run
`./argon2 -h` as
```
Usage:  ./argon2 [-h] salt [-i|-d|-id] [-t iterations] [-m memory] [-p parallelism] [-l hash length] [-e|-r] [-v (10|13)]
        Password is read from stdin
Parameters:
        salt            The salt to use, at least 8 characters
        -i              Use Argon2i (this is the default)
        -d              Use Argon2d instead of Argon2i
        -id             Use Argon2id instead of Argon2i
        -t N            Sets the number of iterations to N (default = 3)
        -m N            Sets the memory usage of 2^N KiB (default 12)
        -p N            Sets parallelism to N threads (default 1)
        -l N            Sets hash output length to N bytes (default 32)
        -e              Output only encoded hash
        -r              Output only the raw bytes of the hash
        -v (10|13)      Argon2 version (defaults to the most recent version, currently 13)
        -h              Print argon2 usage
```
For example, to hash "password" using "somesalt" as a salt and doing 2
iterations, consuming 64 MiB, using four parallel threads and an output hash
of 24 bytes
```
$ echo -n "password" | ./argon2 somesalt -t 2 -m 16 -p 4 -l 24
Type:           Argon2i
Iterations:     2
Memory:         65536 KiB
Parallelism:    4
Hash:           45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6
Encoded:        $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
0.188 seconds
Verification ok
```

### Library

`libargon2` provides an API to both low-level and high-level functions
for using Argon2.

The example program below hashes the string "password" with Argon2i
using the high-level API and then using the low-level API. While the
high-level API takes the three cost parameters (time, memory, and
parallelism), the password input buffer, the salt input buffer, and the
output buffers, the low-level API takes in these and additional parameters
, as defined in [`include/argon2.h`](include/argon2.h).

There are many additional parameters, but we will highlight three of them here.

1. The `secret` parameter, which is used for [keyed hashing](
   https://en.wikipedia.org/wiki/Hash-based_message_authentication_code).
   This allows a secret key to be input at hashing time (from some external
   location) and be folded into the value of the hash. This means that even if
   your salts and hashes are compromized, an attacker cannot brute-force to find
   the password without the key.

2. The `ad` parameter, which is used to fold any additional data into the hash
   value. Functionally, this behaves almost exactly like the `secret` or `salt`
   parameters; the `ad` parameter is folding into the value of the hash.
   However, this parameter is used for different data. The `salt` should be a
   random string stored alongside your password. The `secret` should be a random
   key only usable at hashing time. The `ad` is for any other data.

3. The `flags` parameter, which determines which memory should be securely
   erased. This is useful if you want to securly delete the `pwd` or `secret`
   fields right after they are used. To do this set `flags` to either
   `ARGON2_FLAG_CLEAR_PASSWORD` or `ARGON2_FLAG_CLEAR_SECRET`. To change how
   internal memory is cleared, change the global flag
   `FLAG_clear_internal_memory` (defaults to clearing internal memory).

Here the time cost `t_cost` is set to 2 iterations, the
memory cost `m_cost` is set to 2<sup>16</sup> kibibytes (64 mebibytes),
and parallelism is set to 1 (single-thread).

Compile for example as `gcc test.c libargon2.a -Isrc -o test`, if the program
below is named `test.c` and placed in the project's root directory.

```c
#include "argon2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HASHLEN 32
#define SALTLEN 16
#define PWD "password"

int main(void)
{
    uint8_t hash1[HASHLEN];
    uint8_t hash2[HASHLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *pwd = (uint8_t *)strdup(PWD);
    uint32_t pwdlen = strlen((char *)pwd);

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

    // high-level API
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);

    // low-level API
    argon2_context context = {
        hash2,  /* output array, at least HASHLEN in size */
        HASHLEN, /* digest length */
        pwd, /* password array */
        pwdlen, /* password length */
        salt,  /* salt array */
        SALTLEN, /* salt length */
        NULL, 0, /* optional secret data */
        NULL, 0, /* optional associated data */
        t_cost, m_cost, parallelism, parallelism,
        ARGON2_VERSION_13, /* algorithm version */
        NULL, NULL, /* custom memory allocation / deallocation functions */
        /* by default only internal memory is cleared (pwd is not wiped) */
        ARGON2_DEFAULT_FLAGS
    };

    int rc = argon2i_ctx( &context );
    if(ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    free(pwd);

    for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash1[i] ); printf( "\n" );
    if (memcmp(hash1, hash2, HASHLEN)) {
        for( int i=0; i<HASHLEN; ++i ) {
            printf( "%02x", hash2[i] );
        }
        printf("\nfail\n");
    }
    else printf("ok\n");
    return 0;
}
```

To use Argon2d instead of Argon2i call `argon2d_hash_raw` instead of
`argon2i_hash_raw` using the high-level API, and `argon2d` instead of
`argon2i` using the low-level API. Similarly for Argon2id, call `argon2id_hash_raw`
and `argon2id`.

To produce the crypt-like encoding rather than the raw hash, call
`argon2i_hash_encoded` for Argon2i, `argon2d_hash_encoded` for Argon2d, and
`argon2id_hash_encoded` for Argon2id

See [`include/argon2.h`](include/argon2.h) for API details.

*Note: in this example the salt is set to the all-`0x00` string for the
sake of simplicity, but in your application you should use a random salt.*


### Benchmarks

`make bench` creates the executable `bench`, which measures the execution
time of various Argon2 instances:

```
$ ./bench
Argon2d 1 iterations  1 MiB 1 threads:  5.91 cpb 5.91 Mcycles
Argon2i 1 iterations  1 MiB 1 threads:  4.64 cpb 4.64 Mcycles
0.0041 seconds

Argon2d 1 iterations  1 MiB 2 threads:  2.76 cpb 2.76 Mcycles
Argon2i 1 iterations  1 MiB 2 threads:  2.87 cpb 2.87 Mcycles
0.0038 seconds

Argon2d 1 iterations  1 MiB 4 threads:  3.25 cpb 3.25 Mcycles
Argon2i 1 iterations  1 MiB 4 threads:  3.57 cpb 3.57 Mcycles
0.0048 seconds

(...)

Argon2d 1 iterations  4096 MiB 2 threads:  2.15 cpb 8788.08 Mcycles
Argon2i 1 iterations  4096 MiB 2 threads:  2.15 cpb 8821.59 Mcycles
13.0112 seconds

Argon2d 1 iterations  4096 MiB 4 threads:  1.79 cpb 7343.72 Mcycles
Argon2i 1 iterations  4096 MiB 4 threads:  2.72 cpb 11124.86 Mcycles
19.3974 seconds

(...)
```

## Bindings

Bindings are available for the following languages (make sure to read
their documentation):

* [Elixir](https://github.com/riverrun/argon2_elixir) by [@riverrun](https://github.com/riverrun)
* [Erlang](https://github.com/ergenius/eargon2) by [@ergenius](https://github.com/ergenius)
* [Go](https://github.com/tvdburgt/go-argon2) by [@tvdburgt](https://github.com/tvdburgt)
* [Haskell](https://hackage.haskell.org/package/argon2) by [@hvr](https://github.com/hvr)
* [JavaScript (native)](https://github.com/ranisalt/node-argon2), by [@ranisalt](https://github.com/ranisalt)
* [JavaScript (native)](https://github.com/jdconley/argon2themax), by [@jdconley](https://github.com/jdconley)
* [JavaScript (ffi)](https://github.com/cjlarose/argon2-ffi), by [@cjlarose](https://github.com/cjlarose)
* [JavaScript (browser)](https://github.com/antelle/argon2-browser), by [@antelle](https://github.com/antelle)
* [JVM](https://github.com/phxql/argon2-jvm) by [@phXql](https://github.com/phxql)
* [JVM (with keyed hashing)](https://github.com/kosprov/jargon2-api) by [@kosprov](https://github.com/kosprov)
* [Lua (native)](https://github.com/thibaultCha/lua-argon2) by [@thibaultCha](https://github.com/thibaultCha)
* [Lua (ffi)](https://github.com/thibaultCha/lua-argon2-ffi) by [@thibaultCha](https://github.com/thibaultCha)
* [OCaml](https://github.com/Khady/ocaml-argon2) by [@Khady](https://github.com/Khady)
* [Python (native)](https://pypi.python.org/pypi/argon2), by [@flamewow](https://github.com/flamewow)
* [Python (ffi)](https://pypi.python.org/pypi/argon2_cffi), by [@hynek](https://github.com/hynek)
* [Python (ffi, with keyed hashing)](https://github.com/thusoy/porridge), by [@thusoy](https://github.com/thusoy)
* [R](https://cran.r-project.org/package=argon2) by [@wrathematics](https://github.com/wrathematics)
* [Ruby](https://github.com/technion/ruby-argon2) by [@technion](https://github.com/technion)
* [Rust](https://github.com/quininer/argon2-rs) by [@quininer](https://github.com/quininer)
* [Rust](https://docs.rs/argonautica/) by [@bcmyers](https://github.com/bcmyers/)
* [C#/.NET CoreCLR](https://github.com/kmaragon/Konscious.Security.Cryptography) by [@kmaragon](https://github.com/kmaragon)
* [Perl](https://github.com/Leont/crypt-argon2) by [@leont](https://github.com/Leont)
* [mruby](https://github.com/Asmod4n/mruby-argon2) by [@Asmod4n](https://github.com/Asmod4n)
* [Swift](https://github.com/ImKcat/CatCrypto) by [@ImKcat](https://github.com/ImKcat)


## Test suite

There are two sets of test suites. One is a low level test for the hash
function, the other tests the higher level API. Both of these are built and
executed by running:

`make test`

## Intellectual property

Except for the components listed below, the Argon2 code in this
repository is copyright (c) 2015 Daniel Dinu, Dmitry Khovratovich (main
authors), Jean-Philippe Aumasson and Samuel Neves, and dual licensed under the
[CC0 License](https://creativecommons.org/about/cc0) and the
[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0). For more info
see the LICENSE file.

The string encoding routines in [`src/encoding.c`](src/encoding.c) are
copyright (c) 2015 Thomas Pornin, and under
[CC0 License](https://creativecommons.org/about/cc0).

The BLAKE2 code in [`src/blake2/`](src/blake2) is copyright (c) Samuel
Neves, 2013-2015, and under
[CC0 License](https://creativecommons.org/about/cc0).

All licenses are therefore GPL-compatible.
