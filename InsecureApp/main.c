#include "getopt.h"
#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include <openssl/err.h>
#include <openssl/evp.h>
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
		if (argc == 3 && strcmp(argv[1], "-x") == 0) {
			vault_entry_t* entry_to_extract = vault_get_entry_by_name(vault, argv[2]);

			int write_result = write_vault_entry_data_to_file(entry_to_extract);
			if (write_result == 0) {
        		printf("Contents written successfully!\n");
    		} else {
        		printf("There was an error writing to the file\n");
    		}	
		}

		// Extract all entries
		if (argc == 2 && strcmp(argv[1], "-xa") == 0) {
			int write_result = write_vault_entries_to_files(vault);
			if (write_result == 0) {
        		printf("Contents written successfully!\n");
    		} else {
        		printf("There was an error writing to the files\n");
    		}	
		}

		// Change password
		vault = vault_change_password(vault, "newpassword");
		vault_print(vault);

		// Compare digest - test case
		if (argc == 4 && strcmp(argv[1], "-d") == 0) {
			size_t user_digest_length = strlen(argv[3]);
			if (user_digest_length != SHA256_DIGEST_SIZE * 2) {
				printf("Invalid input: SHA-256 digest must be %d characters long\n", SHA256_DIGEST_SIZE * 2);
				return 1;
			}

			vault_entry_t* entry_to_digest = vault_get_entry_by_name(vault, argv[2]);
			
			if (entry_to_digest != NULL) {
				printf("Found entry:\n");
				printf(" Name: %s\n", entry_to_digest->name);
				printf(" Data: %s\n", entry_to_digest->data);
				printf(" Size: %zu\n",entry_to_digest->size);
			} else {
				printf("Entry not found\n");
				return 1;
			}

			int comparison_result = verify_vault_entry_integrity(entry_to_digest, argv[3]);
			if (comparison_result == 0) {
        		printf("Digests match!\n");
    		} else {
        		printf("Digests do not match\n");
    		}		
		}

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