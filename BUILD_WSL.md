# Compiling hashcat for Windows with Windows Subsystem for Linux.

Tested on a Windows 10 (x64 build 18363), should also work to build hashcat for Windows on Linux.

### Installation ###

Enable WSL.

Run bash (win+r bash) and make sure to install additional dependencies necessary for hashcat compilation
```
sudo apt install gcc-mingw-w64-x86-64 make git
git clone https://github.com/hashcat/hashcat
git clone https://github.com/win-iconv/win-iconv 
cp hashcat/tools/win-iconv-64.diff win-iconv/
cd win-iconv/
sudo make install
```

### Building ###

You've already cloned the latest master revision of hashcat repository above, so switch to the folder and type "make win" to start compiling hashcat
```
cd ../hashcat
make win
```

The process may take a while, please be patient. Once it's finished, run a Windows command prompt (win+r cmd) and start hashcat by typing "hashcat.exe"

```
hashcat.exe
```