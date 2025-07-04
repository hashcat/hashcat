# Compiling hashcat for Windows with Windows Subsystem for Linux 2.

Tested on Windows 11 x64, should also work to build hashcat for Windows on Linux.

I had it tested with WSL2 using "Ubuntu", which at the time of writing is Ubuntu 24.04

Make sure to have the system upgraded after install (otherwise it will fail to find the gcc-mingw-w64-x86-64 package).

### Installation ###

Enable WSL2.

Press the win + r key on your keyboard simultaneously and in the "Run" popup window type bash and make sure to install additional dependencies necessary for hashcat compilation
```bash
sudo apt install build-essential gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 make git zstd python3-dev cmake
git clone https://github.com/hashcat/hashcat
git clone https://github.com/win-iconv/win-iconv
cd win-iconv/
cmake -D WIN_ICONV_BUILD_EXECUTABLE=OFF -D CMAKE_INSTALL_PREFIX=/opt/win-iconv-64 -D CMAKE_CXX_COMPILER=$(which x86_64-w64-mingw32-g++) -D CMAKE_C_COMPILER=$(which x86_64-w64-mingw32-gcc) -D CMAKE_SYSTEM_NAME=Windows
sudo make install
cd ../
wget https://repo.msys2.org/mingw/mingw64/mingw-w64-x86_64-python-3.12.11-1-any.pkg.tar.zst
sudo mkdir /opt/win-python
sudo tar --zstd -xf mingw-w64-x86_64-python-3.12.10-1-any.pkg.tar.zst -C /opt/win-python
```

### Building ###

You've already cloned the latest master revision of hashcat repository above, so switch to the folder and type "make win" to start compiling hashcat
```
cd hashcat/
make win
```

The process may take a while, please be patient. Once it's finished, close WSL.
Press the win + r keys together and (in the "Run" popup window) type cmd, using cd navigate to the hashcat folder e.g.
```
cd "C:\Users\user\hashcat"
```
and start hashcat by typing
```
hashcat.exe
```
