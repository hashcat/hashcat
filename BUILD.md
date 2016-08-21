hashcat build documentation
=
# Revision:
* 1.3

# Authors:
* Gabriele Gristina <<matrix@hashcat.net>>
* Christoph Heuwieser <<dropdead@hashcat.net>>
* magnum <<john.magnum@hushmail.com>>

# Prepare for building

* Get a copy of the **hashcat** repository

```sh
$ git clone https://github.com/hashcat/hashcat.git
$ cd hashcat
```

* Get a copy of the **OpenCL Headers** repository and a copy of .nix windows shims, if you want to build it with Visual Studio

```sh
$ git submodule update --recursive
```

* Install CMake for your OS. You can download it from [official website](https://www.cmake.org/download#latest).
	
* Create build dir
	```sh
	$ mkdir build
	$ cd build
	```

# Create project and build
You can just 
```sh
	cmake ..
```
to select toolchain automatically based on what you have.

## Linux/BSD/Mac
  ```sh
	cmake -G "Unix Makefiles" ..
	make
  ```

## Windows (create nmake makefile)
  ```powershell
	cmake -G "NMake Makefiles" ..
	nmake
  ```
  
## Windows (create Visual Studio project)
  * determine VS version number (for example 14) and year number (for example 2015)
  *
  ```powershell
	cmake -G "Visual Studio <version number> <year number>" ..
	devenv hashcat.sln
  ```
  * Build with VS

## Windows (MinGW)
  * ```powershell
	cmake -G "MinGW Makefiles" ..
	make
  ```
	* If you use CodeBlocks prepend with ```CodeBlocks - ```

# Install hashcat for Linux

The install target is linux FHS compatible and can be used like this:

```sh
$ make install
```

If you install it, cached kernels, session files, restore- and pot-files etc. will go to $HOME/.hashcat/


=
Enjoy your fresh **hashcat** binaries ;)
