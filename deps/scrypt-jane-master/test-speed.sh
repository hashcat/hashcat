#!/bin/sh

test() {
	sleep 0.25 # mingw is stupid and will occasionally not have permission to overwrite scrypt_speed
	gcc scrypt-jane-speed.c -O3 -DSCRYPT_$1 -DSCRYPT_$2 $3 -o scrypt_speed 2>/dev/null
	local RC=$?
	if [ $RC -ne 0 ]; then
		echo "$1/$2: failed to compile "
		return
	fi
	./scrypt_speed
}

testhash() {
	test $1 SALSA $2
	test $1 CHACHA $2
	test $1 SALSA64 $2
}

testhashes() {
	testhash SHA256 $1
	testhash SHA512 $1
	testhash BLAKE256 $1
	testhash BLAKE512 $1
	testhash SKEIN512 $1
	testhash KECCAK256 $1
	testhash KECCAK512 $1
}

if [ -z $1 ]; then
	testhashes
elif [ $1 -eq 32 ]; then
	testhashes -m32
elif [ $1 -eq 64 ]; then
	testhashes -m64
fi

rm -f scrypt_speed