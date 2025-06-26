# Contributing to SSE2NEON

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to [SSE2NEON](https://github.com/DLTcollab/sse2neon),
hosted on GitHub. These are mostly guidelines, not rules. Use your best
judgment, and feel free to propose changes to this document in a pull request.

## Issues

This project uses GitHub Issues to track ongoing development, discuss project plans, and keep track of bugs. Be sure to search for existing issues before you create another one.

Visit our [Issues page on GitHub](https://github.com/DLTcollab/sse2neon/issues) to search and submit.

## Add New Intrinsic

The new intrinsic conversion should be added in the `sse2neon.h` file,
and it should be placed in the correct classification with the alphabetical order.
The classification can be referenced from [Intel Intrinsics Guide](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html).

Classification: `SSE`, `SSE2`, `SSE3`, `SSSE3`, `SSE4.1`, `SSE4.2`

## Coding Convention

We welcome all contributions from corporate, acaddemic and individual developers. However, there are a number of fundamental ground rules that you must adhere to in order to participate. These rules are outlined as follows:
* All code must adhere to the existing C coding style (see below). While we are somewhat flexible in basic style, you will adhere to what is currently in place. Uncommented, complicated algorithmic constructs will be rejected.
* All external pull requests must contain sufficient documentation in the pull request comments in order to be accepted.

Software requirement: [clang-format](https://clang.llvm.org/docs/ClangFormat.html) version 18 or later.

Use the command `$ clang-format -i *.[ch]` to enforce a consistent coding style.

## Naming Conventions

There are some general rules.
* Names with leading and trailing underscores are reserved for system purposes, and most systems use them for names that the user should not have to know.
* Function, typedef, and variable names, as well as struct, union, and enum tag names should be in lower case.
* Many function-like macros are in all CAPS.
* Avoid names that differ only in case, like `foo` and `Foo`. Similarly, avoid `foobar` and `foo_bar`. The potential for confusion is considerable.
* Similarly, avoid names that look like each other. On many terminals and printers, `l`, `1` and `I` look quite similar. A variable named `l` is particularly bad because it looks so much like the constant `1`.

In general, global names (including enums) should have a common prefix (`SSE2NEON_` for macros and enum constants; `_sse2neon_` for functions) identifying the module that they belong with. Globals may alternatively be grouped in a global structure. Typedeffed names often have `_t` appended to their name.

Avoid using names that might conflict with other names used in standard libraries. There may be more library code included in some systems than you need. Your program could also be extended in the future.

## Coding Style for Modern C

This coding style is a variation of the K&R style. Some general principles: honor tradition, but accept progress; be consistent;
embrace the latest C standards; embrace modern compilers, their static analysis
capabilities and sanitizers.

### Indentation

Use 4 spaces rather than tabs.

### Line length

All lines should generally be within 80 characters.  Wrap long lines.
There are some good reasons behind this:
* It forces the developer to write more succinct code;
* Humans are better at processing information in smaller quantity portions;
* It helps users of vi/vim (and potentially other editors) who use vertical splits.

### Comments

Multi-line comments shall have the opening and closing characters
in a separate line, with the lines containing the content prefixed by a space
and the `*` characters for alignment, e.g.,
```c
/*
 * This is a multi-line comment.
 */

/* One line comment. */
```

Use multi-line comments for more elaborative descriptions or before more
significant logical block of code.

Single-line comments shall be written in C89 style:
```c
    return (uintptr_t) val;  /* return a bitfield */
```

Leave two spaces between the statement and the inline comment.

### Spacing and brackets

Use one space after the conditional or loop keyword, no spaces around
their brackets, and one space before the opening curly bracket.

Functions (their declarations or calls), `sizeof` operator or similar
macros shall not have a space after their name/keyword or around the
brackets, e.g.,
```c
unsigned total_len = offsetof(obj_t, items[n]);
unsigned obj_len = sizeof(obj_t);
```

Use brackets to avoid ambiguity and with operators such as `sizeof`,
but otherwise avoid redundant or excessive brackets.

### Variable names and declarations

- Use descriptive names for global variables and short names for locals.
Find the right balance between descriptive and succinct.

- Use [snakecase](https://en.wikipedia.org/wiki/Snake_case).
Do not use "camelcase".

- Do not use Hungarian notation or other unnecessary prefixing or suffixing.

- Use the following spacing for pointers:
```c
const char *name;  /* const pointer; '*' with the name and space before it */
conf_t * const cfg;  /* pointer to a const data; spaces around 'const' */
const uint8_t * const charmap;  /* const pointer and const data */
const void * restrict key;  /* const pointer which does not alias */
```

### Type definitions

Declarations shall be on the same line, e.g.,
```c
typedef void (*dir_iter_t)(void *, const char *, struct dirent *);
```

_Typedef_ structures rather than pointers.  Note that structures can be kept
opaque if they are not dereferenced outside the translation unit where they
are defined.  Pointers can be _typedefed_ only if there is a very compelling
reason.

New types may be suffixed with `_t`.  Structure name, when used within the
translation unit, may be omitted, e.g.:

```c
typedef struct {
    unsigned if_index;
    unsigned addr_len;
    addr_t next_hop;
} route_info_t;
```

### Initialization

Embrace C99 structure initialization where reasonable, e.g.,
```c
static const crypto_ops_t openssl_ops = {
    .create = openssl_crypto_create,
    .destroy = openssl_crypto_destroy,
    .encrypt = openssl_crypto_encrypt,
    .decrypt = openssl_crypto_decrypt,
    .hmac = openssl_crypto_hmac,
};
```

Embrace C99 array initialization, especially for the state machines, e.g.,
```c
static const uint8_t tcp_fsm[TCP_NSTATES][2][TCPFC_COUNT] = {
    [TCPS_CLOSED] = {
        [FLOW_FORW] = {
            /* Handshake (1): initial SYN. */
            [TCPFC_SYN]	= TCPS_SYN_SENT,
        },
    },
    ...
}
```

### Control structures

Try to make the control flow easy to follow.  Avoid long convoluted logic
expressions; try to split them where possible (into inline functions,
separate if-statements, etc).

The control structure keyword and the expression in the brackets should be
separated by a single space.  The opening curly bracket shall be in the
same line, also separated by a single space.  Example:

```c
    for (;;) {
        obj = get_first();
        while ((obj = get_next(obj))) {
            ...
        }
        if (done)
            break;
    }
```

Do not add inner spaces around the brackets. There should be one space after
the semicolon when `for` has expressions:
```c
    for (unsigned i = 0; i < __arraycount(items); i++) {
        ...
    }
```

#### Avoid unnecessary nesting levels

Avoid:
```c
int inspect(obj_t *obj)
{
    if (cond) {
        ...
        /* long code block */
        ...
        return 0;
    }
    return -1;
}
```

Consider:
```c
int inspect(obj_t *obj)
{
    if (!cond)
        return -1;

    ...
    return 0;
}
```

However, do not make logic more convoluted.

### `if` statements

Curly brackets and spacing follow the K&R style:
```c
    if (a == b) {
        ..
    } else if (a < b) {
        ...
    } else {
        ...
    }
```

Simple and succinct one-line if-statements may omit curly brackets:
```c
    if (!valid)
        return -1;
```

However, do prefer curly brackets with multi-line or more complex statements.
If one branch uses curly brackets, then all other branches shall use the
curly brackets too.

Wrap long conditions to the if-statement indentation adding extra 4 spaces:
```c
    if (some_long_expression &&
        another_expression) {
        ...
    }
```

#### Avoid redundant `else`

Avoid:
```c
    if (flag & F_FEATURE_X) {
        ...
        return 0;
    } else {
        return -1;
    }
```

Consider:
```c
    if (flag & F_FEATURE_X) {
        ...
        return 0;
    }
    return -1;
```

### `switch` statements

Switch statements should have the `case` blocks at the same indentation
level, e.g.:
```c
    switch (expr) {
    case A:
        ...
        break;
    case B:
        /* fallthrough */
    case C:
        ...
        break;
    }
```

If the case block does not break, then it is strongly recommended to add a
comment containing "fallthrough" to indicate it.  Modern compilers can also
be configured to require such comment (see gcc `-Wimplicit-fallthrough`).

### Function definitions

The opening and closing curly brackets shall also be in the separate lines (K&R style).

```c
ssize_t hex_write(FILE *stream, const void *buf, size_t len)
{
    ...
}
```

Do not use old style K&R style C definitions.

### Object abstraction

Objects are often "simulated" by the C programmers with a `struct` and
its "public API".  To enforce the information hiding principle, it is a
good idea to define the structure in the source file (translation unit)
and provide only the _declaration_ in the header.  For example, `obj.c`:

```c
#include "obj.h"

struct obj {
    int value;
}

obj_t *obj_create(void)
{
    return calloc(1, sizeof(obj_t));
}

void obj_destroy(obj_t *obj)
{
    free(obj);
}
```

With an example `obj.h`:
```c
#ifndef _OBJ_H_
#define _OBJ_H_

typedef struct obj;

obj_t *obj_create(void);
void obj_destroy(obj_t *);

#endif
```

Such structuring will prevent direct access of the `obj_t` members outside
the `obj.c` source file.  The implementation (of such "class" or "module")
may be large and abstracted within separate source files.  In such case,
consider separating structures and "methods" into separate headers (think of
different visibility), for example `obj_impl.h` (private) and `obj.h` (public).

Consider `crypto_impl.h`:
```c
#ifndef _CRYPTO_IMPL_H_
#define _CRYPTO_IMPL_H_

#if !defined(__CRYPTO_PRIVATE)
#error "only to be used by the crypto modules"
#endif

#include "crypto.h"

typedef struct crypto {
    crypto_cipher_t cipher;
    void *key;
    size_t key_len;
    ...
}
...

#endif
```

And `crypto.h` (public API):

```c
#ifndef _CRYPTO_H_
#define _CRYPTO_H_

typedef struct crypto crypto_t;

crypto_t *crypto_create(crypto_cipher_t);
void crypto_destroy(crypto_t *);
...

#endif
```

### Use reasonable types

Use `unsigned` for general iterators; use `size_t` for general sizes; use
`ssize_t` to return a size which may include an error.  Of course, consider
possible overflows.

Avoid using `uint8_t` or `uint16_t` or other sub-word types for general
iterators and similar cases, unless programming for micro-controllers or
other constrained environments.

C has rather peculiar _type promotion rules_ and unnecessary use of sub-word
types might contribute to a bug once in a while.

### Embrace portability

#### Byte-order

Do not assume x86 or little-endian architecture.  Use endian conversion
functions for operating the on-disk and on-the-wire structures or other
cases where it is appropriate.

#### Types

- Do not assume a particular 32-bit vs 64-bit architecture, e.g., do not
assume the size of `long` or `unsigned long`.  Use `int64_t` or `uint64_t`
for the 8-byte integers.

- Do not assume `char` is signed; for example, on Arm it is unsigned.

- Use C99 macros for constant prefixes or formatting of the fixed-width
types.

Use:
```c
#define	SOME_CONSTANT (UINT64_C(1) << 48)
printf("val %" PRIu64 "\n", SOME_CONSTANT);
```

Do not use:
```c
#define	SOME_CONSTANT (1ULL << 48)
printf("val %lld\n", SOME_CONSTANT);
```

#### Avoid unaligned access

Do not assume unaligned access is safe.  It is not safe on Arm, POWER,
and various other architectures.  Moreover, even on x86 unaligned access
is slower.

#### Avoid extreme portability

Unless programming for micro-controllers or exotic CPU architectures,
focus on the common denominator of the modern CPU architectures, avoiding
the very maximum portability which can make the code unnecessarily cumbersome.

Some examples:
- It is fair to assume `sizeof(int) == 4` since it is the case on all modern
mainstream architectures.  PDP-11 era is long gone.
- Using `1U` instead of `UINT32_C(1)` or `(uint32_t) 1` is also fine.
- It is fair to assume that `NULL` is matching `(uintptr_t) 0` and it is fair
to `memset()` structures with zero.  Non-zero `NULL` is for retro computing.

## References
- [Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html)
- 1999, Brian W. Kernighan and Rob Pike, The Practice of Programming, Addison–Wesley.
- 1993, Bill Shannon, [C Style and Coding Standards for SunOS](https://devnull-cz.github.io/unix-linux-prog-in-c/cstyle.ms.pdf)
