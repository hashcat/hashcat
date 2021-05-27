# Compiling hashcat with msys2.

Tested on a Windows 10 20H2 x64 machine.

### Installation ###

Go to https://www.msys2.org/ and follow the instructions on the main page (steps 1 to 7).

Install additional dependencies required to compile hashcat by running the following commands

```
$ pacman -S git
$ pacman -S make
$ pacman -S gcc
$ pacman -S libiconv-devel
```

### Building ###

Once all that is done, type the following command to copy the latest master revision of hashcat repository into msys64\home\username\hashcat

```
$ git clone https://github.com/hashcat/hashcat.git
```

Switch to the newly created folder by running

```
$ cd hashcat
```

Now type "make" to start compiling hashcat

```
$ make
```

The process may take a while, please be patient. Once it's finished, run hashcat by typing "./hashcat.exe"

```
$ ./hashcat.exe
```

### Notes ###

While hashcat will run fine from msys shell, running it from a windows shell will require msys-iconv-2.dll and msys-2.0.dll to be in the same folder with hashcat.exe (the files can be found in msys64\usr\bin).
