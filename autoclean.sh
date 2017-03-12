#!/bin/sh

chmod 755 $0 autogen.sh config.guess config.rpath config.status config.sub configure depcomp install-sh missing

make clean
make distclean

rm -f *.o

rm -f config.log
rm -f config.status
rm -f config.h
rm -f Makefile
rm -rf ./autom4te.cache/
rm -f gmon.out

#rm -f ./src/Makefile.in
#rm -f ./Makefile.in
