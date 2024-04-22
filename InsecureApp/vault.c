#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"
#include "vault.h"
#include "string.h"

vault_t* vault_new(const char* filename, const char* password, const char* author) {
    vault_t* vault = malloc(sizeof(vault_t));
    vault->head = NULL;
    memcpy(vault->magic, (uint8_t[2]){0x56, 0x41}, 2);
    memcpy(vault->nonce, (uint8_t[4]){0x01, 0x02, 0x03, 0x04}, 4);
    strcpy(vault->filename, filename);
    strcpy(vault->password, password);
    strcpy(vault->author, author);
    return vault;
}

void vault_print(const vault_t* vault) {
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
    printf("+ VAULT %s\n", vault->filename);
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
    printf("| Author: %s\n", vault->author);
    printf("| Password: %s\n", vault->password);
    vault_entry_t* entry = vault->head;
    size_t i = 0;
    while(entry != NULL) {
        printf("-----------------------------------------\n");
        printf("| %d: %s\n", i, entry->name);
        printf("-----------------------------------------\n");
        entry = entry->next;
    }
    printf("\n\n");
}

vault_t* vault_add(vault_t* vault, const char* filename, const char* data) {
    vault_entry_t* entry = malloc(sizeof(vault_entry_t));
    strcpy(entry->name, filename);
    strcpy(entry->data, data);
    entry->next = vault->head;

    vault->head = entry;
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
    return offset;
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

    return offset;
}