/*
	pick the best algo at runtime or compile time?
	----------------------------------------------
	SCRYPT_CHOOSE_COMPILETIME (gcc only!)
	SCRYPT_CHOOSE_RUNTIME
*/
#define SCRYPT_CHOOSE_RUNTIME


/*
	hash function to use
	-------------------------------
	SCRYPT_BLAKE256
	SCRYPT_BLAKE512
	SCRYPT_SHA256
	SCRYPT_SHA512
	SCRYPT_SKEIN512
*/
//#define SCRYPT_SHA256


/*
	block mixer to use
	-----------------------------
	SCRYPT_CHACHA
	SCRYPT_SALSA
*/
//#define SCRYPT_SALSA
