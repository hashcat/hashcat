## Some notes about the --keyboard-layout-mapping feature ##

This new configuration item was added to handle a special TrueCrypt and VeraCrypt "feature" which is automatically active during the setup of encryption for a system partition or an entire system drive. Due to BIOS requirements, the user's keyboard layout is always set to the US keyboard layout during the pre-boot stage (no matter which layout is actually in use). In other words, in the pre-boot stage, when TC/VC asks the user to enter the password, the layout is actually set to the US keyboard layout.

To avoid conflicts with the real keyboard layout configured in the OS, both TC and VC have a little trick: they set the OS keyboard layout to US keyboard layout while the password prompt window is opened. You can actually verify this in the language task bar while the password prompt window is open. It will switch from whatever is configured to English, and after the window is closed, the original keyboard layout is restored.

This has a serious impact on cracking the password. For example, my German keyboard layout is a "QWERTZ" keyboard layout. The US keyboard, however used a "QWERTY" layout. The difference is that the position of the "y" and "z" letter is exchanged. If it was just that, this wouldn't be much of a problem - but almost all the special symbols are mapped very differently. (I won't go into the details; you might want to compare it yourself for fun.)

And when it comes to non-Latin based languages, this behaviour gets completely out of control. Just one example: If the user enters the password بين التخصصات (interdisciplinary) on an Arabic keyboard, the password we need to guess is: fdk hgjowwhj[g.

To deal with all of this, a hashcat user needs to know exactly which keyboard was enabled when the password was entered into the password window during setup. The mapping tables ship in the "tables/layouts" folder. If you know a German keyboard was used, add "--keyboard-layout-mapping tables/layouts/de.table" to the commandline.

Unfortunately, since I don't own all of the existing keyboards, it will be necessary for hashcat users to contribute the rest of the missing mapping tables - ideally, as a GitHub PR. Almost every language I know has special keyboard layouts. There's even a difference between the UK and US layouts.

Here's how you can help. To create a language-specific mapping table, open a text editor, and press every key on the keyboard, starting from the top left to the top right. Press Enter after every key. Use only keys which represent a real character, and ignore control keys such as Backspace, Caps Lock, etc. Then move to the next row below and repeat the process from the left to the right, and so on until you reach the space character. At that point, repeat exactly the same sequence, but with Shift pressed. When done, add a Tab after each character (Tab is used as separator character). Then switch the keyboard layout to English and repeat the entire process exactly in the same order, adding each character after the tab character. Hashcat fully supports all multibyte characters up to 32 bits on both sides of the mapping table (even if the right side will be always a single byte character). As an example, see the tables/layouts/de.table file.

Note that when it comes to Alt/AltGr, this behavior is exploitable. TC/VC does not accept those modifier keys. If a user uses AltGr while entering the password, a window appears that tells the user that the use of this key is not allowed. For instance, on my German keyboard layout, I need to use AltGr+q to get the "@" character. As a consequence of this, we know that the TC/VC password cannot include any of the characters ("@", "[", "]", "\", "€", "|", "{", "}", "~") if the user was using a German keyboard to enter the password.

At the same time, we can guarantee that "@" will never be listed on the left side of the mapping table - because the only characters that can appear there are the ones that are are reachable only without any modifier or by using shift (but not AltGr). If we combine these concepts, we could add some code to reject all passwords which contain at least one character not listed in a mapping table. This is not yet implemented - but I'll add it if hashcat users agree that there is value in it.

## The mapping file format ##

A mapping file is a table file, the same format attack mode 8's table attack reads. One rule to a line: the source token, a tab, then what to put in its place. Blank lines are skipped, lines beginning with # are comments, and a line that does not hold exactly one tab is not a mapping and is passed over. A token that would otherwise be read as a comment, or that carries a tab, is written as $HEX[..]. A file that turns out to hold no mappings at all is refused, rather than converting nothing and saying nothing about it.

Keys that produce the same character in both layouts are left out of the shipped tables. They are what the mapping does not change, so listing them says nothing.

Each language also has a reverse table, tables/layouts/de-reverse.table and so on, which converts the other way, for a wordlist in the US layout whose password was typed with the other layout active. Those are table attack files rather than mapping files. Where two keys of one layout produce the same character on the other, the reverse of that is one character with two replacements, which the table attack offers as a choice and a mapping cannot express at all. hashcat refuses such a file for this option rather than picking one of the two silently.

These files are also tables for the table attack, which converts layouts for any hash mode rather than only for TrueCrypt and VeraCrypt. See hashcat-table.md.
