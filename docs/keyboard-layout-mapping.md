## Keyboard layout mapping ##

The `--keyboard-layout-mapping` option reproduces how TrueCrypt and VeraCrypt system encryption handles keyboard layouts. During pre-boot authentication, the firmware uses a US layout regardless of the layout printed on the physical keyboard.

During setup, both applications temporarily switch the operating system to the US layout while their password prompt is open. They restore the configured layout when the prompt closes. This ensures that the password bytes entered during setup match those produced later during pre-boot authentication.

This behavior matters when cracking the password. A German keyboard uses QWERTZ while a US keyboard uses QWERTY, so `y` and `z` exchange positions and most symbols also move.

The difference is even greater for non-Latin layouts. For example, entering the password بين التخصصات ("interdisciplinary") on an Arabic keyboard produces the password bytes represented by `fdk hgjowwhj[g` under the US layout.

You therefore need to know which physical keyboard layout was used when the password was created. Mapping tables ship in `tables/layouts`. For a German keyboard, add `--keyboard-layout-mapping tables/layouts/de.table` to the command line.

The repository does not include every physical keyboard layout. Contributions of missing mapping tables are welcome as GitHub pull requests. Even closely related layouts, such as UK and US English, require different tables.

To create a language-specific mapping table, open a text editor and press each character-producing key from left to right, beginning with the top row. Press Enter after every key and omit control keys such as Backspace and Caps Lock. Continue row by row through the space bar, then repeat the same sequence while holding Shift.

Add a tab after each recorded character. Switch the operating system to the US layout and repeat the sequence in exactly the same order, placing each new character after the corresponding tab. hashcat accepts tokens of one to four bytes on either side of the tab. See `tables/layouts/de.table` for an example.

TrueCrypt and VeraCrypt reject Alt and AltGr during password entry, which narrows the possible character set. On a German layout, for example, AltGr+q produces `@`. A password created with that layout therefore cannot contain `@`, `[`, `]`, `\`, `€`, `|`, `{`, `}` or `~`.

The left side of a mapping contains only characters reachable without a modifier or with Shift. A character with no mapping is left unchanged.

## The mapping file format ##

A mapping file uses the same format as a table attack (`-a 5`). Each line contains a source token, a tab and its replacement. Blank lines are ignored, lines beginning with `#` are comments, and lines without exactly one tab are skipped. Write a token as `$HEX[...]` if it would otherwise be interpreted as a comment or contains a tab. hashcat rejects a file with no valid mappings instead of silently leaving every candidate unchanged.

Keys that produce the same character in both layouts are left out of the shipped tables. The mapping leaves them unchanged, so listing them provides no additional information.

Each language also has a reverse table, such as `tables/layouts/de-reverse.table`. It converts a US-layout wordlist into candidates typed with the other layout active. Reverse tables are table attack files, not keyboard mapping files.

If two keys in one layout produce the same character in another, the reverse conversion gives one source character two possible replacements. A table attack can offer both choices, but a keyboard mapping cannot represent that ambiguity. hashcat therefore rejects such a file for `--keyboard-layout-mapping` instead of silently choosing one replacement.

These files are also tables for the table attack, which converts layouts for any hash mode rather than only for TrueCrypt and VeraCrypt. See `hashcat-table.md`.
