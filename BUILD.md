hashcat build documentation
=
# Revision:
* 1.4

# Author: see docs/credits.txt

# Building hashcat for Linux, macOS and Windows (using Cygwin or MSYS2)

Get a copy of the **hashcat** repository

```sh
$ git clone https://github.com/hashcat/hashcat.git
```

Run "make"

```sh
$ make
```

# Install hashcat for Linux

The install target is linux FHS compatible and can be used like this:

```sh
$ make install
```

If you install it, cached kernels, session files, restore- and pot-files etc. will go to $HOME/.hashcat/

# Building hashcat for Windows from Linux

```sh
$ make win
```

=
Enjoy your fresh **hashcat** binaries ;)
