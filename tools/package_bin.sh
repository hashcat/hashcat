#!/usr/bin/env sh

##
## Author......: See docs/credits.txt
## License.....: MIT
##

export VERSION=7.1.2
export MAJOR=${VERSION%%.*}

export IN=.
export OUT=$HOME/xy/hashcat-$VERSION

# what the archive is laid out around: a frontend per platform and the core each one shares with its
# plugins. A make that stopped early leaves some of them behind, and packing what is there produces
# an archive that looks ordinary and cannot run, so the name of the missing one is said here instead

for artifact in hashcat.bin hashcat.exe libhashcat.so.$MAJOR hashcat.dll; do

  if [ -f "$IN/$artifact" ]; then
    continue
  fi

  echo "! $artifact was not built. The archive is laid out around it, so nothing is packed."
  exit 1

done

rm -rf $OUT
rm -rf $OUT.7z

mkdir -p $OUT

mkdir -p $OUT/tools
mkdir -p $OUT/Python
mkdir -p $OUT/Rust/hashcat-sys
mkdir -p $OUT/Rust/bridges/generic_hash
mkdir -p $OUT/Rust/bridges/dynamic_hash

cp    $IN/hashcat.exe                   $OUT/
cp    $IN/hashcat.bin                   $OUT/
cp    $IN/hashcat.hcstat2               $OUT/

# the core each binary and its plugins share. On Linux it is found beside hashcat.bin and one
# directory above every plugin, on Windows it is found beside hashcat.exe, so the archive is
# unpacked and run with nothing set in the environment

cp    $IN/libhashcat.so.$MAJOR          $OUT/
cp    $IN/hashcat.dll                   $OUT/

cp -r $IN/docs                          $OUT/
cp -r $IN/charsets                      $OUT/
cp -r $IN/layouts                       $OUT/
cp -r $IN/masks                         $OUT/
cp -r $IN/bridges                       $OUT/
cp -r $IN/feeds                         $OUT/
cp -r $IN/modules                       $OUT/
cp -r $IN/rules                         $OUT/
cp -r $IN/extra                         $OUT/
cp -r $IN/tunings                       $OUT/
cp    $IN/example.dict                  $OUT/
cp    $IN/example[0123456789]*.hash     $OUT/
cp    $IN/example[0123456789]*.cmd      $OUT/
cp -r $IN/Python/*.py                   $OUT/Python/
cp -r $IN/Rust/hashcat-sys/src                  $OUT/Rust/hashcat-sys/
cp    $IN/Rust/hashcat-sys/Cargo.*              $OUT/Rust/hashcat-sys/
cp    $IN/Rust/hashcat-sys/build.rs             $OUT/Rust/hashcat-sys/
cp -r $IN/Rust/bridges/generic_hash/src         $OUT/Rust/bridges/generic_hash/
cp    $IN/Rust/bridges/generic_hash/Cargo.*     $OUT/Rust/bridges/generic_hash/
cp    $IN/Rust/bridges/generic_hash/build.rs    $OUT/Rust/bridges/generic_hash/
cp -r $IN/Rust/bridges/dynamic_hash/src         $OUT/Rust/bridges/dynamic_hash/
cp    $IN/Rust/bridges/dynamic_hash/Cargo.*     $OUT/Rust/bridges/dynamic_hash/
cp    $IN/Rust/bridges/dynamic_hash/build.rs    $OUT/Rust/bridges/dynamic_hash/
cp -r $IN/OpenCL                        $OUT/
cp    $IN/tools/*hashcat.pl             $OUT/tools/
cp    $IN/tools/*hashcat.py             $OUT/tools/

# since for the binary distribution we still use .bin, we need to rewrite the commands
# within the example*.sh files

for example in example[0123456789]*.sh; do

  sed 's!./hashcat !./hashcat.bin !' $IN/${example} > $OUT/${example}

done

dos2unix $OUT/layouts/*.hckmap
dos2unix $OUT/masks/*.hcmask
dos2unix $OUT/rules/*.rule
dos2unix $OUT/rules/hybrid/*.rule
dos2unix $OUT/docs/*
dos2unix $OUT/docs/license_libs/*
dos2unix $OUT/example*
dos2unix $OUT/tools/*
dos2unix $OUT/tunings/*

unix2dos $OUT/layouts/*.hckmap
unix2dos $OUT/masks/*.hcmask
unix2dos $OUT/rules/*.rule
unix2dos $OUT/rules/hybrid/*.rule
unix2dos $OUT/docs/*
unix2dos $OUT/docs/license_libs/*
unix2dos $OUT/example*.cmd
unix2dos $OUT/Python/*
unix2dos $OUT/OpenCL/*
unix2dos $OUT/tools/*
unix2dos $OUT/tunings/*

chmod 755 $OUT
chmod 755 $OUT/rules
chmod 644 $OUT/rules/*
chmod 755 $OUT/rules/hybrid
chmod 644 $OUT/rules/hybrid/*
chmod 755 $OUT/docs
chmod 644 $OUT/docs/*
chmod 755 $OUT/docs/license_libs
chmod 644 $OUT/docs/license_libs/*
chmod 755 $OUT/charsets
chmod 755 $OUT/charsets/*
chmod 755 $OUT/layouts
chmod 644 $OUT/layouts/*
chmod 755 $OUT/masks
chmod 644 $OUT/masks/*
chmod 755 $OUT/bridges
chmod 644 $OUT/bridges/*
chmod 755 $OUT/bridges/subs
chmod 644 $OUT/bridges/subs/*
chmod 755 $OUT/feeds
chmod 644 $OUT/feeds/*
chmod 755 $OUT/modules
chmod 644 $OUT/modules/*
chmod 644 $OUT/example*
chmod 755 $OUT/example*.sh
chmod 755 $OUT/extra
chmod 755 $OUT/extra/tab_completion/*.sh
chmod 755 $OUT/extra/tab_completion/install
chmod 755 $OUT/Python
chmod 644 $OUT/Python/*
chmod 755 $OUT/Rust
#chmod 644 $OUT/Python/*
chmod 755 $OUT/OpenCL
chmod 644 $OUT/OpenCL/*
chmod 755 $OUT/tunings
chmod 644 $OUT/tunings/*
chmod 644 $OUT/*.exe
chmod 644 $OUT/*.dll
chmod 755 $OUT/*.bin
chmod 755 $OUT/libhashcat.so.$MAJOR
chmod 644 $OUT/hashcat.hcstat2
chmod 755 $OUT/tools/*hashcat.pl
chmod 755 $OUT/tools/*hashcat.py

time 7z a -t7z -m0=lzma2:d31 -mx=9 -mmt=8 -ms=on $OUT.7z $OUT
