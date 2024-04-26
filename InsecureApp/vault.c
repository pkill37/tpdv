#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include "vault.h"
#include "string.h"


vault_t* vault_new(const char* filename, const char* password, const char* author) {
    vault_t* vault = malloc(sizeof(vault_t));
    vault->head = NULL;
    memcpy(vault->magic, (uint8_t[2]){0x56, 0x41}, 2);
    for (int i = 0; i < 4; i++) vault->nonce[i] = rand() % 256;
    strcpy(vault->filename, filename);
    strcpy(vault->password, password);
    strcpy(vault->author, author);
    return vault;
}

size_t vault_total_size(const vault_t* vault) {
    //size_t size = sizeof(vault->nonce) + sizeof(vault->magic) + sizeof(vault->filename) + sizeof(vault->password) + sizeof(vault->author) + sizeof(vault->size) + sizeof(vault->head);
    size_t size = sizeof(vault_t);
    size += vault->size * sizeof(vault_entry_t);
    return size;
}

void vault_print(const vault_t* vault) {
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
    printf("+ VAULT %s\n", vault->filename);
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
    printf("+ Author: %s\n", vault->author);
    printf("+ Password: %s\n", vault->password);
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
    vault_entry_t* entry = vault->head;
    size_t i = 0;
    while(entry != NULL) {
        printf("| %d: %s\n", i, entry->name);
        printf("-----------------------------------------\n");
        entry = entry->next;
        i++;
    }
    printf("\n\n");
}

int vault_authenticate(const vault_t* vault, const char* password) {
    return strcmp(vault->password, password) == 0;
}

vault_t* vault_add(vault_t* vault, const char* filename, const char* data) {
    vault_entry_t* entry = malloc(sizeof(vault_entry_t));
    strcpy(entry->name, filename);
    strcpy(entry->data, data);
    //strlen will not work with binary files -> use get_file_size()
    entry->size = strlen(data);
    entry->next = vault->head;

    vault->head = entry;
    vault->size++;
    return vault;
}

vault_t* vault_change_password(vault_t* vault, const char* password) {
    strcpy(vault->password, password);
    return vault;
}

// Serialize a VaultEntry
size_t vault_entry_serialize(const vault_entry_t *entry, char *buffer) {
    size_t offset = 0;
    memcpy(buffer + offset, entry->name, sizeof(entry->name));
    offset += sizeof(entry->name);
    memcpy(buffer + offset, entry->data, VAULT_ENTRY_SIZE);
    offset += VAULT_ENTRY_SIZE;
    memcpy(buffer + offset, &entry->size, sizeof(entry->size));
    offset += sizeof(entry->size);
    return offset;
}

void vault_entry_print(const vault_entry_t *entry) {
    printf("Entry: %s\n", entry->name);
    printf("Data: %s\n", entry->data);
    printf("Size: %zu\n", entry->size);
}

// Serialize a Vault
size_t vault_serialize(const vault_t *vault, char *buffer) {
    size_t offset = 0;
    memcpy(buffer + offset, vault->nonce, sizeof(vault->nonce));
    offset += sizeof(vault->nonce);
    memcpy(buffer + offset, vault->magic, sizeof(vault->magic));
    offset += sizeof(vault->magic);
    memcpy(buffer + offset, vault->filename, sizeof(vault->filename));
    offset += sizeof(vault->filename);
    memcpy(buffer + offset, vault->password, sizeof(vault->password));
    offset += sizeof(vault->password);
    memcpy(buffer + offset, vault->author, sizeof(vault->author));
    offset += sizeof(vault->author);
    memcpy(buffer + offset, &vault->size, sizeof(vault->size));
    offset += sizeof(vault->size);

    // Serialize each VaultEntry
    vault_entry_t *current_entry = vault->head;
    while (current_entry != NULL) {
        offset += vault_entry_serialize(current_entry, buffer + offset);
        current_entry = current_entry->next;
    }
    //printf("\n\nhere: %s \n\n", vault->filename);

    return offset;
}


void vault_free(vault_t* vault) {
    vault_entry_t* entry = vault->head;
    while(entry != NULL) {
        vault_entry_t* next = entry->next;
        free(entry);
        entry = next;
    }
    free(vault);
}

// Handle digest errors and cleanup
int handle_errors(EVP_MD_CTX* mdctx) {
  ERR_print_errors_fp(stderr);
  if (mdctx) EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  return 1;
}

// Initialize OpenSSL
void init_openssl() {
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();
}

// Get the chosen digest algorithm
const EVP_MD* get_digest(const char* digest_name) {
  const EVP_MD* digest = EVP_get_digestbyname(digest_name);
  if (!digest) {
    fprintf(stderr, "Error: Could not get digest\n");
  }
  return digest;
}

// Create and initialize the digest context
EVP_MD_CTX* create_digest_ctx(const EVP_MD* digest) {
  EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
  if (!mdctx) {
    fprintf(stderr, "Error: Could not create digest context\n");
  } else if (EVP_DigestInit_ex(mdctx, digest, NULL) != 1) {
    fprintf(stderr, "Error: Could not initialize digest context\n");
    handle_errors(mdctx);  // Already closed fp in error handling
    return NULL;
  }
  return mdctx;
}

// Read vault entry data, update digest, and handle errors
int process_data(const char* data, size_t data_size, EVP_MD_CTX* mdctx) {
  unsigned char buffer[DIGEST_BUF_SIZE];
  size_t bytes_left = data_size;

  while (bytes_left > 0) {
    size_t bytes_to_read = bytes_left > DIGEST_BUF_SIZE ? DIGEST_BUF_SIZE : bytes_left;
    memcpy(buffer, data, bytes_to_read);  // Copy data to buffer

    if (EVP_DigestUpdate(mdctx, buffer, bytes_to_read) != 1) {
      fprintf(stderr, "Error updating digest\n");
      return handle_errors(mdctx);
    }

    data += bytes_to_read;
    bytes_left -= bytes_to_read;
  }

  return 1;
}

// Finalize the digest and get the message digest
int get_message_digest(EVP_MD_CTX* mdctx, unsigned char* md_value, unsigned int* md_len) {
  if (EVP_DigestFinal_ex(mdctx, md_value, md_len) != 1) {
    fprintf(stderr, "Error finalizing digest\n");
    return handle_errors(mdctx);  // Already closed fp in error handling
  }
  return 1;
}

int compare_digests(const char* user_digest, const unsigned char* calculated_digest, unsigned int md_len) {
  if (strlen(user_digest) != SHA256_DIGEST_SIZE * 2) {
    fprintf(stderr, "Invalid user digest format\n");
    return -1;
  }

  // Convert user_digest from hex string to binary byte array
  unsigned char user_digest_binary[SHA256_DIGEST_SIZE];
  for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
    sscanf(user_digest + i * 2, "%02hhx", &user_digest_binary[i]);
  }

  int result = 0;
  for (unsigned int i = 0; i < md_len; i++) {
    result |= (user_digest_binary[i] != calculated_digest[i]);
  }

  return result == 0 ? 0 : 1;
}

// Find a vault entry by name
vault_entry_t* vault_get_entry_by_name(vault_t* vault, const char* name) {
  vault_entry_t* current = vault->head;
  while (current != NULL) {
    if (strcmp(current->name, name) == 0) {
      return current;
    }
    current = current->next;
  }
  return NULL;
}

int verify_vault_entry_integrity(vault_entry_t* entry, const char* user_digest){
    // Space for max digest length in hex
    char processed_digest[EVP_MAX_MD_SIZE * 2 + 1];
    strcpy(processed_digest, user_digest);
    // Remove trailing newline from fgets
    processed_digest[strcspn(processed_digest, "\n")] = '\0';

    // Initialize OpenSSL
    init_openssl();
    const EVP_MD* digest = get_digest("sha256");
    if (!digest) {
        return handle_errors(NULL);
    }

    // Create digest context
    EVP_MD_CTX* mdctx = create_digest_ctx(digest);
    if (!mdctx) {
        return handle_errors(NULL);
    }

    // Process entry data and update digest
    if (process_data(entry->data, entry->size, mdctx) != 1) {
        return handle_errors(mdctx);
    }

    // Finalize the digest for the given file
    unsigned char calculated_digest[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    if (get_message_digest(mdctx, calculated_digest, &md_len) != 1) {
        return handle_errors(mdctx);
    }

    // Convert the calculated digest to a hex string for user display
    char calculated_digest_hex[EVP_MAX_MD_SIZE * 2 + 1];
    for (int i = 0; i < md_len; i++) {
        sprintf(calculated_digest_hex + i * 2, "%02x", calculated_digest[i]);
    }
    calculated_digest_hex[md_len * 2] = '\0';

    printf("Calculated SHA-256 digest: %s\n", calculated_digest_hex);

    // Compare digests
    int comparison_result = compare_digests(processed_digest, calculated_digest, md_len);
    if (comparison_result == -1) {
        return handle_errors(mdctx); // Error handling from compare_digests
    }

    // Clean up
    EVP_MD_CTX_destroy(mdctx);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    return comparison_result;
}

long get_file_size(FILE *fp) {
  if (fp == NULL) {
    return -1;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    return -1;
  }

  long size = ftell(fp);
  if (size < 0) {
    return -1;
  }

  // Rewind the file pointer for further operations
  rewind(fp);

  return size;
}

