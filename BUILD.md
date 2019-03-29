hashcat build documentation
=

### Revision ###

* 1.4

### Author ###

See docs/credits.txt

### Building hashcat for Linux and macOS ###

Get a copy of the **hashcat** repository

```
$ git clone https://github.com/hashcat/hashcat.git
```

Run "make"

```
$ make
```

### Install hashcat for Linux ###

The install target is linux FHS compatible and can be used like this:

```
$ make install
```

If you install it, cached kernels, session files, restore- and pot-files etc. will go to $HOME/.hashcat/

### Building hashcat for Windows (using Cygwin) ###

Refer to [BUILD_CYGWIN.md](BUILD_CYGWIN.md)

### Building hashcat for Windows (using MSYS2) ###

Refer to [BUILD_MSYS2.md](BUILD_MSYS2.md)

### Building hashcat for Windows from Linux ###

```
$ make win
```

=
Enjoy your fresh **hashcat** binaries ;)
