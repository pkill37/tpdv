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
	// Create a new vault
    vault_t* vault = vault_new("vault.dat", "password", "author");
	vault_print(vault);
	if(vault_authenticate(vault, "password")) {
		printf("Authenticated\n");
		// Add a new entry
		vault = vault_add(vault, "entry1", "data1");
		vault = vault_add(vault, "entry2", "data2");
		vault_print(vault);

		// List all entries
		vault_entry_t* entry = vault->head;
		while(entry != NULL) {
			vault_entry_print(entry);
			entry = entry->next;
		}

		// Extract entry

		// Change password
		vault = vault_change_password(vault, "newpassword");
		vault_print(vault);

		// Compare digest

	} else {
		printf("Authentication failed\n");
		exit(1);
	}

	printf("Should be %d bytes\n", vault_total_size(vault));
	char buffer[vault_total_size(vault)];
	size_t sz = vault_serialize(vault, buffer);
	printf("Serialized %d bytes to %s\n", sz, vault->filename);
	hexdump(buffer, sz);	
	FILE* file = fopen(vault->filename, "wb");
	fwrite(buffer, 1, sz, file);
	fclose(file);


	vault_free(vault);

	return 0;
}