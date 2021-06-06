hashcat build documentation
=

### Revision ###

* 1.5

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

If the $HOME/.hashcat folder exists, then:

- Session related files go to: $HOME/.hashcat/sessions/
- Cached kernels go to: $HOME/.hashcat/kernels/
- Potfiles go to: $HOME/.hashcat/

Otherwise, if environment variable XDG_DATA_HOME and XDG_CACHE_HOME exists, then:

- Session related files go to: $XDG_DATA_HOME/hashcat/sessions/
- Cached kernels go to: $XDG_CACHE_HOME/hashcat/kernels/
- Potfiles go to: $XDG_DATA_HOME/hashcat/

Otherwise, if environment variable XDG_DATA_HOME exists, then:

- Session related files go to: $XDG_DATA_HOME/hashcat/sessions/
- Cached kernels go to: $HOME/.cache/hashcat
- Potfiles go to: $XDG_DATA_HOME/hashcat/

Otherwise, if environment variable XDG_CACHE_HOME exists, then:

- Session related files go to: $HOME/.local/share/hashcat/sessions/
- Cached kernels go to: $XDG_CACHE_HOME/hashcat/kernels/
- Potfiles go to: $HOME/.local/share/hashcat/

Otherwise:

- Session related files go to: $HOME/.local/share/hashcat/sessions/
- Cached kernels go to: $HOME/.cache/hashcat
- Potfiles go to: $HOME/.local/share/hashcat/

### Building hashcat for Windows (using Windows Subsystem for Linux) ###

Refer to [BUILD_WSL.md](BUILD_WSL.md)

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
