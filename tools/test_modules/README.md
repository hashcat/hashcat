### Hashcat test modules ###

Each module provides the functions `module_constraints`, `module_generate_hash` and `module_verify_hash`.

* The `module_constraints` function should return the minimum and maximum length of the password, salt and the combination of password and salt in following order: password (pure), salt (pure), password (optimized), salt (optimized) and combination (optimized).
Each pair should be set to -1 if the hash mode is not supporting the appropriate field. For example, if a hash-mode does not support a salt, it should be set to -1. The last field (combination) is important if the password and the salt is stored in the same buffer in the kernel (typically raw hashes only).
* The first parameter to `module_generate_hash` is the password, which can be either in ASCII or binary (packed) form. The second parameter is the salt *which can be undefined for unsalted hash modes).
* The `module_verify_hash` function accepts a line from the cracks file, without the newline characters.

During `single` and `passthrough` tests the `module_generate_hash` function must provide random values (e.g. salt) for hash generation if necessary. The test.pl script offers a few handy functions like `random_hex_string`, `random_numeric_string` and `random_bytes`. You can implement your own salt generation functions, if your mode has specific requirements.

During `verify` tests the `module_verify_hash` function must parse the hash:password line and calculate a hash by passing all necessary data to `module_generate_hash`. How you pass it is up to you, as long as the first parameter is the password.

**Important**: You have to call `pack_if_HEX_notation` as soon as you have parsed the password, or your tests will fail on passwords in the `$HEX[...]` format.

If the algorithm has ambiguous hashes (e.g. partial case-insensitivity), the test module can provide an optional function `module_preprocess_hashlist`. It receives a reference to the hashlist array and can unify the hashes in a way that guarantees the match with the output of `module_verify_hash`.

#### Examples ####

* For the most basic test modules, see [m00000.pm](m00000.pm) and [m00100.pm](m00100.pm)
* For the basic salted hash tests, see [m00110.pm](m00110.pm) and [m00120.pm](m00120.pm)
* For some slightly more complex modules with PBKDF2 and encryption, see [m18400.pm](m18400.pm) and [m18600.pm](m18600.pm)
* For a test module with hashlist preprocessing and a custom salt generation algorithm, see [m05600.pm](m05600.pm)

