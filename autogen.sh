#!/bin/sh

./autoclean.sh

rm -f configure

rm -f Makefile.in

rm -f config.guess
rm -f config.sub
rm -f install-sh
rm -f missing
rm -f depcomp

if [ 0 = 1 ]; then
autoscan
else

touch NEWS
touch README
touch AUTHORS
touch ChangeLog
touch config.h.in
touch install-sh

libtoolize --force --copy --install --automake
aclocal
automake -a -c
autoconf
# run twice to get rid of 'ltmain.sh not found'
autoreconf -f -i -Wall,no-obsolete
autoreconf -f -i -Wall,no-obsolete

#./configure --enable-static --enable-shared --disable-debug
./configure --enable-static --disable-shared --disable-debug

#make clean
make ChangeLog

#make
#make check
#make -C doc/latex/
make dist-gzip

fi
