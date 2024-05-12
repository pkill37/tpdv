#include "Vault.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include "Enclave1_u.h"
#include "sgx_urts.h"
#include "stdint.h"
#include "stdio.h"
#include <dirent.h>
#include "stdlib.h"
#include "string.h"

vault_t* vault_new(const char* filename, const char* password, const char* author) {
  vault_t* vault = (vault_t*)malloc(sizeof(vault_t));
  vault->head = NULL;
  uint8_t magic[2] = {0x56, 0x41};
  memcpy(vault->magic, magic, 2);
  for (int i = 0; i < 4; i++) vault->nonce[i] = rand() % 256;
  strcpy(vault->filename, filename);
  strcpy(vault->password, password);
  strcpy(vault->author, author);
  vault->size = 0;
  return vault;
}

size_t vault_total_size(const vault_t* vault) {
  // size_t size = sizeof(vault->nonce) + sizeof(vault->magic) +
  // sizeof(vault->filename) + sizeof(vault->password) + sizeof(vault->author) +
  // sizeof(vault->size) + sizeof(vault->head);
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
  while (entry != NULL) {
    printf("| %zu: %s\n", i, entry->name);
    printf("-----------------------------------------\n");
    entry = entry->next;
    i++;
  }
  printf("\n\n");
}

int vault_authenticate(const vault_t* vault, const char* password) { return strcmp(vault->password, password) == 0; }

vault_t* vault_add(vault_t* vault, const char* filename, const char* data) {
  vault_entry_t* entry = (vault_entry_t*)malloc(sizeof(vault_entry_t));
  char *parsed_filename = get_filename(filename);
  strcpy(entry->name, parsed_filename);
  strcpy(entry->data, data);
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
size_t vault_entry_serialize(const vault_entry_t* entry, char* buffer) {
  size_t offset = 0;
  memcpy(buffer + offset, entry->name, sizeof(entry->name));
  offset += sizeof(entry->name);
  memcpy(buffer + offset, entry->data, VAULT_ENTRY_SIZE);
  offset += VAULT_ENTRY_SIZE;
  memcpy(buffer + offset, &entry->size, sizeof(entry->size));
  offset += sizeof(entry->size);
  return offset;
}

void vault_entry_print(const vault_entry_t* entry) {
  printf("Entry: %s\n", entry->name);
  printf("Data: %s\n", entry->data);
  printf("Size: %zu\n", entry->size);
}

// Serialize a Vault
size_t vault_serialize(const vault_t* vault, char* buffer) {
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
  vault_entry_t* current_entry = vault->head;
  while (current_entry != NULL) {
    offset += vault_entry_serialize(current_entry, buffer + offset);
    current_entry = current_entry->next;
  }

  return offset;
}

// Deserialize a VaultEntry
vault_entry_t *vault_entry_deserialize(const uint8_t *buffer, size_t *offset) {
  vault_entry_t *entry = (vault_entry_t*)malloc(sizeof(vault_entry_t));
  if (entry == NULL) {
    fprintf(stderr, "Error allocating memory for vault_entry_t\n");
    return NULL;
  }

  memcpy(entry->name, buffer + *offset, sizeof(entry->name));
  *offset += sizeof(entry->name);
  memcpy(entry->data, buffer + *offset, VAULT_ENTRY_SIZE);
  *offset += VAULT_ENTRY_SIZE;
  memcpy(&entry->size, buffer + *offset, sizeof(entry->size));
  *offset += sizeof(entry->size);
  entry->next = NULL;

  return entry;
}

// Deserialize a Vault
vault_t *vault_deserialize(const uint8_t *buffer, size_t buffer_size) {
  vault_t *vault = (vault_t*)malloc(sizeof(vault_t));
  if (vault == NULL) {
    fprintf(stderr, "Error allocating memory for vault_t\n");
    return NULL;
  }

  size_t offset = 0;

  memcpy(vault->nonce, buffer + offset, sizeof(vault->nonce));
  offset += sizeof(vault->nonce);
  memcpy(vault->magic, buffer + offset, sizeof(vault->magic));
  offset += sizeof(vault->magic);
  memcpy(vault->filename, buffer + offset, sizeof(vault->filename));
  offset += sizeof(vault->filename);
  memcpy(vault->password, buffer + offset, sizeof(vault->password));
  offset += sizeof(vault->password);
  memcpy(vault->author, buffer + offset, sizeof(vault->author));
  offset += sizeof(vault->author);
  memcpy(&vault->size, buffer + offset, sizeof(vault->size));
  offset += sizeof(vault->size);

  // Deserialize VaultEntries
  vault->head = NULL;
  vault_entry_t **current_entry_ptr = &vault->head;

  while (offset < buffer_size) {
    // Check if the next entry appears empty (e.g., name and data filled with zeros)
    if (buffer[offset + 1] == 0) {
      break; // No more entries to deserialize
    }

    *current_entry_ptr = vault_entry_deserialize(buffer, &offset);
    if (*current_entry_ptr == NULL) {
      // Error in deserializing a vault entry, free the partially deserialized vault
      vault_free(vault); 
      return NULL;
    }
    current_entry_ptr = &((*current_entry_ptr)->next);
  }

  return vault;
}

void vault_free(vault_t* vault) {
  vault_entry_t* entry = vault->head;
  while (entry != NULL) {
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
static void init_openssl() {
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();
}

// Get the chosen digest algorithm
static const EVP_MD* get_digest(const char* digest_name) {
  const EVP_MD* digest = EVP_get_digestbyname(digest_name);
  if (!digest) {
    fprintf(stderr, "Error: Could not get digest\n");
  }
  return digest;
}

// Create and initialize the digest context
static EVP_MD_CTX* create_digest_ctx(const EVP_MD* digest) {
  EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
  if (!mdctx) {
    fprintf(stderr, "Error: Could not create digest context\n");
  } else if (EVP_DigestInit_ex(mdctx, digest, NULL) != 1) {
    fprintf(stderr, "Error: Could not initialize digest context\n");
    handle_errors(mdctx);
    return NULL;
  }
  return mdctx;
}

// Read vault entry data, update digest, and handle errors
static int process_data(const char* data, size_t data_size, EVP_MD_CTX* mdctx) {
  unsigned char buffer[DIGEST_BUF_SIZE];
  size_t bytes_left = data_size;

  while (bytes_left > 0) {
    size_t bytes_to_read = bytes_left > DIGEST_BUF_SIZE ? DIGEST_BUF_SIZE : bytes_left;
    memcpy(buffer, data, bytes_to_read);

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
static int get_message_digest(EVP_MD_CTX* mdctx, unsigned char* md_value, unsigned int* md_len) {
  if (EVP_DigestFinal_ex(mdctx, md_value, md_len) != 1) {
    fprintf(stderr, "Error finalizing digest\n");
    return handle_errors(mdctx);
  }
  return 1;
}

static int compare_digests(const char* user_digest, const unsigned char* calculated_digest, unsigned int md_len) {
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
  char *parsed_filename = get_filename(name);
  while (current != NULL) {
    if (strcmp(current->name, parsed_filename) == 0) {
      return current;
    }
    current = current->next;
  }
  return NULL;
}

int verify_vault_entry_integrity(vault_entry_t* entry, const char* user_digest) {
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
    return handle_errors(mdctx);  // Error handling from compare_digests
  }

  // Clean up
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  return comparison_result;
}

int calculate_file_digest(const char* filename, const char* data, size_t size) {
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
  if (process_data(data, size, mdctx) != 1) {
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

  printf("Calculated SHA-256 digest for '%s': %s\n", filename, calculated_digest_hex);

  // Clean up
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  return 0;
}

int write_vault_entries_to_files(const vault_t* vault) {
  if (vault == NULL) {
    fprintf(stderr, "Vault not found\n");
    return -1;
  }

  vault_entry_t* current_entry = vault->head;
  while (current_entry != NULL) {
    int write_result = write_vault_entry_data_to_file(current_entry);
    if (write_result != 0) {
      return write_result;
    }

    current_entry = current_entry->next;
  }

  return 0;
}

int write_vault_entry_data_to_file(const vault_entry_t* entry) {
  if (entry == NULL) {
    fprintf(stderr, "Entry not found\n");
    return -1;
  }

  FILE* fp = fopen(entry->name, "wb");
  if (fp == NULL) {
    fprintf(stderr, "Error opening the file descriptor\n");
    return -1;
  }

  // Writes the vault entry data to the file, trimming it to the size specified
  // in the 'entry->size' field
  size_t elements_written = fwrite(entry->data, sizeof(char), entry->size, fp);
  if (elements_written != entry->size) {
    fprintf(stderr, "Error writing vault entry to file\n");
    fclose(fp);
    return -1;
  }

  fclose(fp);
  return 0;
}

uint8_t *load_vault_contents(const char *filename, size_t *file_size) {
  if (filename == NULL) {
    fprintf(stderr, "Error: Invalid filename (NULL)\n");
    return NULL;
  }

  // Validate filename length
  if (strlen(filename) >= 32) {
    fprintf(stderr, "Error: Filename cannot exceed %d characters (including null terminator).\n", 32 - 1);
    return NULL;
  }

  FILE *fp = fopen(filename, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error: Could not open file '%s'\n", filename);
    return NULL;
  }

  // Get file size
  fseek(fp, 0, SEEK_END);
  *file_size = ftell(fp);
  rewind(fp);

  // Allocate memory for file contents
  uint8_t *data = (uint8_t *)malloc(*file_size);
  if (data == NULL) {
    fprintf(stderr, "Error: Memory allocation failed\n");
    fclose(fp);
    return NULL;
  }

  // Read file contents into the array
  size_t bytes_read = fread(data, 1, *file_size, fp);
  if (bytes_read != *file_size) {
    fprintf(stderr, "Error: Could not read entire file\n");
    free(data);
    fclose(fp);
    return NULL;
  }

  fclose(fp);

  return data;
}

int process_vault(sgx_enclave_id_t global_eid1, const char* filename, const char* user_password) {
  sgx_status_t ret, ecall_status;
  size_t file_size;

  // Read vault file
  uint8_t* vault_file_contents = load_vault_contents(filename, &file_size);
  if (vault_file_contents == NULL) {
    fprintf(stderr, "Error: Unable to open vault file '%s'.", filename);
    return EXIT_FAILURE;
  }

  printf("File loaded successfully!\n");
  printf("File size: %zu bytes\n", file_size);

  // Unseal vault
  ecall_status = e1_unseal_data(global_eid1, &ret, vault_file_contents, file_size, user_password);
  if (ecall_status != SGX_SUCCESS || ret != SGX_SUCCESS) {
    fprintf(stderr, "Error: Failed to unseal vault data.\n");
    free(vault_file_contents);
    return EXIT_FAILURE;
  }
  
  free(vault_file_contents);
  return EXIT_SUCCESS;
}

int read_and_parse_file(const char *filename, char *parsed_content, size_t *size) {
  FILE *fp;
  size_t bytes_read;

  fp = fopen(filename, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error: Unable to open file '%s'.\n", filename);
    return -1;
  }

  // Check file size and ensure it fits the vault entry structure
  if (fseek(fp, 0, SEEK_END) != 0) {
    fprintf(stderr, "Error: Error seeking file position.\n");
    fclose(fp);
    return -1;
  }
  long file_size = ftell(fp);
  if (file_size == -1) {
    fprintf(stderr, "Error: Error getting file size.\n");
    fclose(fp);
    return -1;
  }
  if (file_size >= VAULT_ENTRY_SIZE) {
    fprintf(stderr, "Error: File size (%ld bytes) exceeds maximum (%d bytes).\n",file_size, VAULT_ENTRY_SIZE);
    fclose(fp);
    return -1;
  }
  rewind(fp);

  bytes_read = fread(parsed_content, 1, file_size, fp);
  if (bytes_read != file_size) {
    fprintf(stderr, "Error: Error reading from file.\n");
    fclose(fp);
    return -1;
  }
  *size = bytes_read;

  parsed_content[bytes_read] = '\0';

  fclose(fp);

  return 0; 
}

char *get_filename(const char *path) {
  const char *filename = strrchr(path, '/');

  // no path separator (just filename)
  if (filename == NULL) {
    filename = path;
  } else {
    // Point to the character after the separator
    filename++;
  }

  return (char *)filename;
}

int file_exists_in_current_dir(const char *filename) {
  DIR *dir = opendir(".");

  if (dir == NULL) {
    perror("Error opening directory"); 
    return 0;
  }

  struct dirent *entry;
  // Iterate over directory entries
  while ((entry = readdir(dir)) != NULL) { 
    if (strcmp(entry->d_name, filename) == 0) {
      closedir(dir);
      return 1;
    }
  }

  closedir(dir);
  return 0;
}