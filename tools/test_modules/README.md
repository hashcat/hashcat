### Hashcat test modules ###

Each module provides the two functions `module_generate_hash` and `module_verify_hash`. The first parameter to `module_generate_hash` is the password, which can be either in ASCII or binary (packed) form. The `module_verify_hash` function accepts a line from the cracks file, without the newline characters.

During `single` and `passthrough` tests the `module_generate_hash` function must provide random values (e.g. salt) for hash generation if necessary. The test.pl script offers a few handy functions like `random_hex_string`, `random_numeric_string` and `random_bytes`. You can implement your own salt generation functions, if your mode has specific requirements.

During `verify` tests the `module_verify_hash` function must parse the hash:password line and to calculate a hash by passing all necessary data to `module_generate_hash`. How you pass it is up to you, as long as the first parameter is the password.

**Important**: You have to call `pack_if_HEX_notation` as soon as you have parsed the password, or your tests will fail on passwords in the `$HEX[...]` format.
