echo "[*] Testing m00600_a3.cl function _s04"

./hashcat -m 600 --potfile-disable --weak-hash-threshold 0 -u1 -n1 --force  -a 3 b2test.hash_s ?d?d?d?d?d?d

echo "[*] Testing m00600_a3.cl function _m04"

./hashcat -m 600 --potfile-disable --weak-hash-threshold 0 -u1 -n1 --force  -a 3 b2test.hash ?d?d?d?d?d?d

echo "[*] Testing m00600_a0.cl function _s04"

./hashcat -m 600 --potfile-disable --weak-hash-threshold 0 -u1 -n1 --force  -a 0 b2test.hash_s example.dict

echo "[*] Testing m00600_a0.cl function _m04"

./hashcat -m 600 --potfile-disable --weak-hash-threshold 0 -u1 -n1 --force  -a 0 b2test.hash example.dict

echo "[*] Testing m00600_a1.cl function _s04"

./hashcat -m 600 --potfile-disable --weak-hash-threshold 0 -u1 -n1 --force  -a 1 b2test.hash example.dict example.dict

echo "[*] Testing m00600_a1.cl function _m04"

./hashcat -m 600 --potfile-disable --weak-hash-threshold 0 -u1 -n1 --force  -a 1 b2test.hash example.dict example.dict
