## Some notes about the --keyboard-layout-mapping feature ##

The `--keyboard-layout-mapping` option handles how TrueCrypt and VeraCrypt system encryption treats keyboard layouts. During pre-boot authentication, the firmware uses a US keyboard layout regardless of the layout printed on the keyboard.

During setup, both applications temporarily switch the operating system to the US layout while their password prompt is open. They restore the configured layout when the prompt closes. This makes the password bytes entered during setup match the bytes produced later at pre-boot.

This matters when cracking the password. A German keyboard is QWERTZ while a US keyboard is QWERTY, so `y` and `z` exchange positions and most symbols move as well.

And when it comes to non-Latin based languages, this behaviour gets completely out of control. Just one example: If the user enters the password بين التخصصات (interdisciplinary) on an Arabic keyboard, the password we need to guess is: fdk hgjowwhj[g.

You therefore need to know which physical keyboard layout was used when the password was created. Mapping tables ship in `tables/layouts`. For a German keyboard, add `--keyboard-layout-mapping tables/layouts/de.table` to the command line.

Unfortunately, since I don't own all of the existing keyboards, it will be necessary for hashcat users to contribute the rest of the missing mapping tables - ideally, as a GitHub PR. Almost every language I know has special keyboard layouts. There's even a difference between the UK and US layouts.

Here's how you can help. To create a language-specific mapping table, open a text editor, and press every key on the keyboard, starting from the top left to the top right. Press Enter after every key. Use only keys which represent a real character, and ignore control keys such as Backspace, Caps Lock, etc. Then move to the next row below and repeat the process from the left to the right, and so on until you reach the space character. At that point, repeat exactly the same sequence, but with Shift pressed. When done, add a Tab after each character (Tab is used as separator character). Then switch the keyboard layout to English and repeat the entire process exactly in the same order, adding each character after the tab character. Hashcat accepts one- to four-byte tokens on both sides of the mapping table. As an example, see the tables/layouts/de.table file.

Note that when it comes to Alt/AltGr, this behavior is exploitable. TC/VC does not accept those modifier keys. If a user uses AltGr while entering the password, a window appears that tells the user that the use of this key is not allowed. For instance, on my German keyboard layout, I need to use AltGr+q to get the "@" character. As a consequence of this, we know that the TC/VC password cannot include any of the characters ("@", "[", "]", "\", "€", "|", "{", "}", "~") if the user was using a German keyboard to enter the password.

The left side of a mapping contains only characters reachable without a modifier or with Shift. A character with no mapping is left unchanged.

## The mapping file format ##

A mapping file uses the same table format as the table attack (`-a 5`). One rule to a line: the source token, a tab, then what to put in its place. Blank lines are skipped, lines beginning with # are comments, and a line that does not hold exactly one tab is not a mapping and is passed over. A token that would otherwise be read as a comment, or that carries a tab, is written as $HEX[..]. A file that turns out to hold no mappings at all is refused, rather than converting nothing and saying nothing about it.

Keys that produce the same character in both layouts are left out of the shipped tables. They are what the mapping does not change, so listing them says nothing.

Each language also has a reverse table, tables/layouts/de-reverse.table and so on, which converts the other way, for a wordlist in the US layout whose password was typed with the other layout active. Those are table attack files rather than mapping files. Where two keys of one layout produce the same character on the other, the reverse of that is one character with two replacements, which the table attack offers as a choice and a mapping cannot express at all. hashcat refuses such a file for this option rather than picking one of the two silently.

These files are also tables for the table attack, which converts layouts for any hash mode rather than only for TrueCrypt and VeraCrypt. See hashcat-table.md.
