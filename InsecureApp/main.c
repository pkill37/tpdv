#include "getopt.h"
#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"
#include "vault.h"

#define APP_NAME    "TPDV"
#define APP_VERSION "1.0.0"

void hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int main(int argc, char *argv[]) {
    vault_t* vault = vault_new("vault.dat", "password", "author");
	vault_print(vault);

	char buffer[VAULT_ENTRY_SIZE];
	size_t sz = vault_serialize(vault, buffer);
	printf("Serialized %d bytes to %s\n", sz, vault->filename);
	hexdump(buffer, sz);	

	return 0;
}