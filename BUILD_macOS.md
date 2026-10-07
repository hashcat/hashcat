# Compiling hashcat for Windows with macOS.

This is about cross compiling a Windows binary on a Mac, so it says nothing about what a machine
running hashcat needs. For that see docs/hashcat-requirements.md, which asks for macOS 13.0 to use
Metal or Apple's OpenCL.

Make sure to have the HomeBrew upgraded.

### Installation ###

```
brew install mingw-w64
git clone https://github.com/hashcat/hashcat
```

### Building ###

You've already cloned the latest master revision of hashcat repository above, so switch to the folder and type "make win" to start compiling hashcat
```
cd hashcat/
make win
```

The process may take a while, please be patient.
