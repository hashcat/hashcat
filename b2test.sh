./hashcat -m 600 -a 0 b2test.hash b2test.dict --opencl-vector-width=1 -u1 -n1 --force --weak-hash-threshold=0 --potfile-disable
