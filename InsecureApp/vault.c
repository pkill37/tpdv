#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"
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
    return offset;
}

void vault_entry_print(const vault_entry_t *entry) {
    printf("Entry: %s\n", entry->name);
    printf("Data: %s\n", entry->data);
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


void vault_free(vault_t* vault) {
    vault_entry_t* entry = vault->head;
    while(entry != NULL) {
        vault_entry_t* next = entry->next;
        free(entry);
        entry = next;
    }
    free(vault);
}