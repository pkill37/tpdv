#pragma once

#define VAULT_ENTRY_SIZE 5000000

typedef struct VaultEntry vault_entry_t;
struct VaultEntry {
    char name[32];
    char data[VAULT_ENTRY_SIZE];

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