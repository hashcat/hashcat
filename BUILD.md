hashcat build documentation
=

### Revision ###

* 1.7

### Author ###

See docs/credits.txt

### Building hashcat

Check your python3 version

```
$ python3 --version
Python 3.13.3
```

If you cannot globally install a version of python >= 3.12, you can use pyenv. If you want to use pyenv please follow all the steps described below, otherwise only steps 3 and 5.

### Building hashcat - Step 1

#### Linux

Install deps for build python3 with pyenv

```
$ sudo apt install libbz2-dev libssl-dev libncurses5-dev libffi-dev libreadline-dev libsqlite3-dev liblzma-dev
```

Install pyenv and follow the instructions at the end to properly set up your environment

```
$ curl https://pyenv.run | bash
```

#### macOS

Install pyenv and follow the instructions at the end to properly set up your environment

```
$ brew install pyenv
```

### Building hashcat - Step 2

Install python 3.12 (or or higher) with pyenv

```
$ pyenv install 3.12
```

Get the precise python3 version to activate

```
$ pyenv versions
* system (set by [...]/.pyenv/version)
  3.12.11
```

### Building hashcat - Step 3

Get a copy of the **hashcat** repository

```
$ git clone https://github.com/hashcat/hashcat.git
$ cd hashcat
```

### Building hashcat - Step 4

Sets a local application-specific Python version for hashcat

```
$ pyenv local 3.12.11
```

### Building hashcat - Step 5

Build hashcat

```
$ make clean && make
```

### Building hashcat - Step 6 (optional)

#### Install hashcat for Linux ####

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

### Building hashcat binaries using Docker ###

Refer to [BUILD_Docker.md](BUILD_Docker.md)

### Building hashcat for Windows (using macOS) ###

Refer to [BUILD_macOS.md](BUILD_macOS.md)

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
