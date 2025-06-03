#include <stdio.h>
#include "scrypt-jane.h"


int main(void) {
	unsigned char digest[16];
	int i;
	scrypt("pw", 2, "salt", 4, 0, 0, 0, digest, 16);
	for (i = 0; i < sizeof(digest); i++)
		printf("%02x, ", digest[i]);
	printf("\n");
	return 0;
}