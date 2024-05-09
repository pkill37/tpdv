#pragma once

#define VAULT_ENTRY_SIZE 500
#define DIGEST_BUF_SIZE 4096
#define SHA256_DIGEST_SIZE 32

typedef struct VaultEntry vault_entry_t;
struct VaultEntry {
    char name[32];
    char data[VAULT_ENTRY_SIZE];
    size_t size;

    vault_entry_t* next;
};

typedef struct Vault vault_t;
struct Vault {
    uint8_t nonce[4];
    uint8_t magic[2];
    char filename[32];
    char password[32];
    char author[32];
    size_t size;

    vault_entry_t* head;
};

vault_t* vault_new(const char* filename, const char* password, const char* author);
void vault_print(const vault_t* vault);
vault_t* vault_add(vault_t* vault, const char* filename, const char* data);
vault_t* vault_change_password(vault_t* vault, const char* password);
size_t vault_entry_serialize(const vault_entry_t *entry, char *buffer);
size_t vault_serialize(const vault_t *vault, char *buffer);

size_t vault_total_size(const vault_t* vault);
int vault_authenticate(const vault_t* vault, const char* password);
void vault_free(vault_t* vault);
void vault_entry_print(const vault_entry_t *entry);

int handle_errors(EVP_MD_CTX* mdctx);
void init_openssl();
const EVP_MD* get_digest(const char* digest_name);
EVP_MD_CTX* create_digest_ctx(const EVP_MD* digest);
int process_data(const char* data, size_t data_size, EVP_MD_CTX* mdctx);
int get_message_digest(EVP_MD_CTX* mdctx, unsigned char* md_value, unsigned int* md_len);
int compare_digests(const char* user_digest, const unsigned char* calculated_digest, unsigned int md_len);
vault_entry_t* vault_get_entry_by_name(vault_t* vault, const char* name);
int verify_vault_entry_integrity(vault_entry_t* entry, const char* user_digest);
long get_file_size(FILE *fp);
int write_vault_entries_to_files(const vault_t* vault);
int write_vault_entry_data_to_file(const vault_entry_t* entry);