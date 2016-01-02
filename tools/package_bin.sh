#!/bin/bash

##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

export IN=$HOME/oclHashcat
export OUT=$HOME/xy/oclHashcat-2.01

rm -rf $OUT
rm -rf $OUT.7z

mkdir -p $OUT $OUT/kernels $OUT/kernels/4098 $OUT/kernels/4318

cp    $IN/oclHashcat??.exe                      $OUT/
cp    $IN/oclHashcat??.bin                      $OUT/
cp    $IN/hashcat.hcstat                        $OUT/

cp -r $IN/docs                                  $OUT/
cp -r $IN/charsets                              $OUT/
cp -r $IN/masks                                 $OUT/
cp -r $IN/rules                                 $OUT/
cp -r $IN/extra                                 $OUT/
cp    $IN/example.dict                          $OUT/
cp    $IN/example[0123456789]*.hash             $OUT/
cp    $IN/example[0123456789]*.sh               $OUT/
cp    $IN/example[0123456789]*.cmd              $OUT/

cp -r $IN/include                               $OUT/
cp -r $IN/OpenCL                                $OUT/

dos2unix $OUT/rules/*.rule
dos2unix $OUT/rules/hybrid/*.rule
dos2unix $OUT/docs/*
dos2unix $OUT/example*

unix2dos $OUT/masks/*.hcmask
unix2dos $OUT/rules/*.rule
unix2dos $OUT/rules/hybrid/*.rule
unix2dos $OUT/docs/*
unix2dos $OUT/example*.cmd

chmod 700 $OUT
chmod 700 $OUT/kernels
chmod 700 $OUT/kernels/4098
chmod 700 $OUT/kernels/4318
chmod 700 $OUT/rules
chmod 600 $OUT/rules/*
chmod 700 $OUT/docs
chmod 600 $OUT/docs/*
chmod 700 $OUT/charsets
chmod 700 $OUT/charsets/*
chmod 700 $OUT/masks
chmod 600 $OUT/masks/*
chmod 600 $OUT/example*
chmod 700 $OUT/example*.sh
chmod 700 $OUT/extra
chmod 700 $OUT/extra/tab_completion/*.sh
chmod 700 $OUT/extra/tab_completion/install
chmod 700 $OUT/include
chmod 600 $OUT/include/*
chmod 700 $OUT/OpenCL
chmod 600 $OUT/OpenCL/*
chmod 600 $OUT/*.exe
chmod 700 $OUT/*.bin
chmod 600 $OUT/hashcat.hcstat

time 7z a -t7z -m0=lzma2:d31 -mx=9 -mmt=8 -ms=on $OUT.7z $OUT
