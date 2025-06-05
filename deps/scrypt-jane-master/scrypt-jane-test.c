#define SCRYPT_TEST
#include "scrypt-jane.c"

int main(void) {
	int res = scrypt_power_on_self_test();

	printf("%s: test %s\n", SCRYPT_MIX, (res & 1) ? "ok" : "FAILED");
	printf("%s: test %s\n", SCRYPT_HASH, (res & 2) ? "ok" : "FAILED");
	printf("scrypt: test vectors %s\n", (res & 4) ? "ok" : "FAILED");

	return ((res & 7) == 7) ? 0 : 1;
}
