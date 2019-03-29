hashcat build documentation
=

### Revision ###

* 1.4

### Author ###

See docs/credits.txt

### Building hashcat for Linux, macOS and Windows (using Cygwin) ###

Get a copy of the **hashcat** repository

```
$ git clone https://github.com/hashcat/hashcat.git
```

Run "make"

```
$ make
```

### Building hashcat for Windows (using MSYS2) ###

Refer to [BUILD_MSYS2.md](BUILD_MSYS2.md)

### Install hashcat for Linux ###

The install target is linux FHS compatible and can be used like this:

```
$ make install
```

If you install it, cached kernels, session files, restore- and pot-files etc. will go to $HOME/.hashcat/

### Building hashcat for Windows from Linux ###

```
$ make win
```

=
Enjoy your fresh **hashcat** binaries ;)
