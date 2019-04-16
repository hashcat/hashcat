#!/bin/bash

hash1=password
hash2=password1938
hash3=0v3rl0rd
hash4=adsadlajlkdjaldjldkjsakldjklsajdlajdsadsad
hash5=1285password
potfile=/home/therek/.hashcat/hashcat.potfile

function testing {
	
	echo -e "\n\n=============================================================================="
	echo test $2 enc password is $1
	echo -n $1 | $2 | cut -b -$4 > hash.txt
	cat hash.txt
	hashcat -m $3 -a 0 hash.txt passwords_10000.txt > /dev/null
	
	echo checking potfile, should contain $5 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	rm -f $potfile hash.txt
}

function testing_mask_a {
	
	echo -e "\n\n=============================================================================="
	echo test $2 enc password is $1
	echo -n $1 | $2 | cut -b -$4 > hash.txt
	cat hash.txt
	hashcat -m $3 -a 6 --increment --increment-min=1 hash.txt passwords_10000.txt ?d?d?d?d > /dev/null
	echo checking potfile, should contain $5 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	rm -f $potfile hash.txt

}

function testing_mask_b {
	
	echo -e "\n\n=============================================================================="
	echo test $2 enc password is $1
	echo -n $1 | $2 | cut -b -$4 > hash.txt
	cat hash.txt
	hashcat -m $3 -a 7 --increment --increment-min=1 hash.txt ?d?d?d?d passwords_10000.txt > /dev/null
	echo checking potfile, should contain $5 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	rm -f $potfile hash.txt

}

function testing_r {
	
	echo -e "\n\n=============================================================================="
	echo test $2 enc password is $1
	echo -n $1 | $2 | cut -b -$4 > hash.txt
	cat hash.txt
	hashcat -m $3 -a 0 -r r.rules hash.txt passwords_10000.txt > /dev/null
	
	echo checking potfile, should contain $5 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	rm -f $potfile hash.txt
}

function testing_mask_a_r {
	
	echo -e "\n\n=============================================================================="
	echo test $2 enc password is $1
	echo -n $1 | $2 | cut -b -$4 > hash.txt
	cat hash.txt
	hashcat -m $3 -a 0 -r r.rules -r app_4_dig.rules hash.txt passwords_10000.txt > /dev/null
	echo checking potfile, should contain $5 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	rm -f $potfile hash.txt

}
 
function testing_mask_b_r {
	
	echo -e "\n\n=============================================================================="
	echo test $2 enc password is $1
	echo -n $1 | $2 | cut -b -$4 > hash.txt
	cat hash.txt
	hashcat -m $3 -a 0 -r r.rules -r pre_app_4_dig.rules hash.txt passwords_10000.txt > /dev/null
	echo checking potfile, should contain $5 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	rm -f $potfile hash.txt

}

function testing_multi {
	
	echo -e "\n\n=============================================================================="
	echo test $6 enc password is $1
	echo -n $1 | $6 | cut -b -$8 > hash.txt
	echo -n $2 | $6 | cut -b -$8 >> hash.txt
	echo -n $3 | $6 | cut -b -$8 >> hash.txt
	echo -n $4 | $6 | cut -b -$8 >> hash.txt
	echo -n $5 | $6 | cut -b -$8 >> hash.txt
	cat hash.txt
	hashcat -m $7 -a 0 hash.txt passwords_10000.txt > /dev/null
	
	echo checking potfile, should contain $9 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	echo "List of hashes and passwords"
	cat $potfile
	rm -f $potfile hash.txt
}

function testing_multi_a {
	
	echo -e "\n\n=============================================================================="
	echo test $6 enc password is $1
	echo -n $1 | $6 | cut -b -$8 > hash.txt
	echo -n $2 | $6 | cut -b -$8 >> hash.txt
	echo -n $3 | $6 | cut -b -$8 >> hash.txt
	echo -n $4 | $6 | cut -b -$8 >> hash.txt
	echo -n $5 | $6 | cut -b -$8 >> hash.txt
	cat hash.txt
	hashcat -m $7 -a 6 --increment hash.txt passwords_10000.txt ?d?d?d?d > /dev/null
	
	echo checking potfile, should contain $9 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	echo "List of hashes and passwords"
	cat $potfile
	rm -f $potfile hash.txt
}

function testing_multi_b {
	
	echo -e "\n\n=============================================================================="
	echo test $6 enc password is $1
	echo -n $1 | $6 | cut -b -$8 > hash.txt
	echo -n $2 | $6 | cut -b -$8 >> hash.txt
	echo -n $3 | $6 | cut -b -$8 >> hash.txt
	echo -n $4 | $6 | cut -b -$8 >> hash.txt
	echo -n $5 | $6 | cut -b -$8 >> hash.txt
	cat hash.txt
	hashcat -m $7 -a 7 --increment hash.txt ?d?d?d?d passwords_10000.txt > /dev/null
	
	echo checking potfile, should contain $9 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	echo "List of hashes and passwords"
	cat $potfile
	rm -f $potfile hash.txt
}

function testing_multi_r {
	
	echo -e "\n\n=============================================================================="
	echo test $6 enc password is $1
	echo -n $1 | $6 | cut -b -$8 > hash.txt
	echo -n $2 | $6 | cut -b -$8 >> hash.txt
	echo -n $3 | $6 | cut -b -$8 >> hash.txt
	echo -n $4 | $6 | cut -b -$8 >> hash.txt
	echo -n $5 | $6 | cut -b -$8 >> hash.txt
	cat hash.txt
	hashcat -m $7 -a 0 -r r.rules hash.txt passwords_10000.txt > /dev/null
	
	echo checking potfile, should contain $9 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	echo "List of hashes and passwords"
	cat $potfile
	rm -f $potfile hash.txt
}

function testing_multi_r_a {
	
	echo -e "\n\n=============================================================================="
	echo test $6 enc password is $1
	echo -n $1 | $6 | cut -b -$8 > hash.txt
	echo -n $2 | $6 | cut -b -$8 >> hash.txt
	echo -n $3 | $6 | cut -b -$8 >> hash.txt
	echo -n $4 | $6 | cut -b -$8 >> hash.txt
	echo -n $5 | $6 | cut -b -$8 >> hash.txt
	cat hash.txt
	hashcat -m $7 -a 0 -r r.rules -r app_4_dig.rules hash.txt passwords_10000.txt > /dev/null
	
	echo checking potfile, should contain $9 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	echo "List of hashes and passwords"
	cat $potfile
	rm -f $potfile hash.txt
}

function testing_multi_r_b {
	
	echo -e "\n\n=============================================================================="
	echo test $6 enc password is $1
	echo -n $1 | $6 | cut -b -$8 > hash.txt
	echo -n $2 | $6 | cut -b -$8 >> hash.txt
	echo -n $3 | $6 | cut -b -$8 >> hash.txt
	echo -n $4 | $6 | cut -b -$8 >> hash.txt
	echo -n $5 | $6 | cut -b -$8 >> hash.txt
	cat hash.txt
	hashcat -m $7 -a 0 -r r.rules -r pre_app_4_dig.rules hash.txt passwords_10000.txt > /dev/null
	
	echo checking potfile, should contain $9 line\(s\)

	echo -n "NUM Passwords Cracked: "
	wc -l $potfile | cut -b -1
	echo "List of hashes and passwords"
	cat $potfile
	rm -f $potfile hash.txt
}

echo remove found hashes

rm -f $potfile

echo -e "\n\n***************************************begin sha256 phase********************************************\n\n"

echo -e "\n\n=======================================Testing without mask============================\n\n"

testing $hash1 sha256sum 1400 64 1
testing $hash2 sha256sum 1400 64 0
testing $hash3 sha256sum 1400 64 0
testing $hash4 sha256sum 1400 64 0
testing $hash5 sha256sum 1400 64 0

echo -e "\n\n=======================================Testing with post mask of 1 to 4 digits============================\n\n"

testing_mask_a $hash1 sha256sum 1400 64 0
testing_mask_a $hash2 sha256sum 1400 64 1
testing_mask_a $hash3 sha256sum 1400 64 0
testing_mask_a $hash4 sha256sum 1400 64 0
testing_mask_a $hash5 sha256sum 1400 64 0

echo -e "\n\n=======================================Testing with pre mask of 1 to 4 digits============================\n\n"

testing_mask_b $hash1 sha256sum 1400 64 0
testing_mask_b $hash2 sha256sum 1400 64 0
testing_mask_b $hash3 sha256sum 1400 64 0
testing_mask_b $hash4 sha256sum 1400 64 0
testing_mask_b $hash5 sha256sum 1400 64 1

echo -e "\n\n***************************************begin md5 phase********************************************\n\n"


echo -e "\n\n=======================================Testing without mask============================\n\n"

testing $hash1 md5sum 0 32 1
testing $hash2 md5sum 0 32 0
testing $hash3 md5sum 0 32 0
testing $hash4 md5sum 0 32 0
testing $hash5 md5sum 0 32 0

echo -e "\n\n=======================================Testing with post mask of 1 to 4 digits============================\n\n"

testing_mask_a $hash1 md5sum 0 32 0
testing_mask_a $hash2 md5sum 0 32 1
testing_mask_a $hash3 md5sum 0 32 0
testing_mask_a $hash4 md5sum 0 32 0
testing_mask_a $hash5 md5sum 0 32 0

echo -e "\n\n=======================================Testing with pre mask of 1 to 4 digits============================\n\n"

testing_mask_b $hash1 md5sum 0 32 1
testing_mask_b $hash2 md5sum 0 32 0
testing_mask_b $hash3 md5sum 0 32 0
testing_mask_b $hash4 md5sum 0 32 0
testing_mask_b $hash5 md5sum 0 32 1

echo -e "\n\n***************************************begin rules phase(sha256)********************************************\n\n"

echo -e "\n\n=======================================Testing without mask============================\n\n"

testing_r $hash1 sha256sum 1400 64 1
testing_r $hash2 sha256sum 1400 64 0
testing_r $hash3 sha256sum 1400 64 0
testing_r $hash4 sha256sum 1400 64 0
testing_r $hash5 sha256sum 1400 64 0

echo -e "\n\n=======================================Testing with post mask of 1 to 4 digits============================\n\n"

testing_mask_a_r $hash1 sha256sum 1400 64 0
testing_mask_a_r $hash2 sha256sum 1400 64 1
testing_mask_a_r $hash3 sha256sum 1400 64 0
testing_mask_a_r $hash4 sha256sum 1400 64 0
testing_mask_a_r $hash5 sha256sum 1400 64 0

echo -e "\n\n=======================================Testing with pre mask of 1 to 4 digits============================\n\n"

testing_mask_b_r $hash1 sha256sum 1400 64 0
testing_mask_b_r $hash2 sha256sum 1400 64 0
testing_mask_b_r $hash3 sha256sum 1400 64 0
testing_mask_b_r $hash4 sha256sum 1400 64 0
testing_mask_b_r $hash5 sha256sum 1400 64 1

echo -e "\n\n***************************************begin multi-crack phase (sha256)********************************************\n\n"

testing_multi $hash1 $hash2 $hash3 $hash4 $hash5 sha256sum 1400 64 1
testing_multi_a $hash1 $hash2 $hash3 $hash4 $hash5 sha256sum 1400 64 1
testing_multi_b $hash1 $hash2 $hash3 $hash4 $hash5 sha256sum 1400 64 1
testing_multi_r $hash1 $hash2 $hash3 $hash4 $hash5 sha256sum 1400 64 2
testing_multi_r_a $hash1 $hash2 $hash3 $hash4 $hash5 sha256sum 1400 64 3
testing_multi_r_b $hash1 $hash2 $hash3 $hash4 $hash5 sha256sum 1400 64 3
