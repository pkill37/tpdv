/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave1.h"

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "Enclave1_t.h" /* e1_print_string */
#include "sgx_error.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"

int ret;

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;

  va_start(ap, fmt);
  (void)vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_e1_print_string(buf);
  return 0;
}

/*
 * DH key exchange data (4 more ECALLs)
 */

static sgx_dh_session_t e1_session;
static sgx_key_128bit_t e1_aek;
static sgx_dh_session_enclave_identity_t e1_responder_identity;

// step 1
void e1_init_session(sgx_status_t* dh_status) {
  *dh_status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &e1_session);
}

// step 5
void e1_process_message1(const sgx_dh_msg1_t* msg1, sgx_dh_msg2_t* msg2, sgx_status_t* dh_status) {
  *dh_status = sgx_dh_initiator_proc_msg1(msg1, msg2, &e1_session);
}

// step 9
void e1_process_message3(const sgx_dh_msg3_t* msg3, sgx_status_t* dh_status) {
  *dh_status = sgx_dh_initiator_proc_msg3(msg3, &e1_session, &e1_aek, &e1_responder_identity);
}

void e1_show_secret_key(void) {
  printf("Enclave 1 AEK:");
  for (int i = 0; i < 16; i++) printf(" %02X", 0xFF & (int)e1_aek[i]);
  printf("\n");
}

// Method to encrypt data with e1_aek using SGX encryption API
sgx_status_t e1_encrypt_data(const uint8_t* plain_text, uint32_t plain_text_length, uint8_t* cipher_text, uint32_t cipher_text_length) {
    if (plain_text == NULL || cipher_text == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t iv[12] = {0}; // Initialization vector (IV) for AES-GCM, should be unique for each encryption

    sgx_status_t status = sgx_rijndael128GCM_encrypt(&e1_aek, plain_text, plain_text_length, cipher_text, iv, sizeof(iv), NULL, 0, NULL);
    return status;
}

// Method to decrypt data with e1_aek using SGX decryption API
sgx_status_t e1_decrypt_data(const uint8_t* cipher_text, uint32_t cipher_text_length, uint8_t* plain_text, uint32_t plain_text_length) {
    if (cipher_text == NULL || plain_text == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint8_t iv[12] = {0}; // Initialization vector (IV) for AES-GCM, should match the IV used for encryption

    sgx_status_t status = sgx_rijndael128GCM_decrypt(&e1_aek, cipher_text, cipher_text_length, plain_text, iv, sizeof(iv), NULL, 0, NULL);
    return status;
}

// Retrieve a substring from a character buffer
static char* getSubstring(const char* buffer, int start, int length) {
  int bufferLength = strlen(buffer);

  // Ensure start index is within bounds
  if (start < 0 || start >= bufferLength) {
    return NULL;
  }

  // Calculate the actual length of the substring
  int substringLength = (start + length <= bufferLength) ? length : (bufferLength - start);

  char* substring = (char*)malloc((substringLength + 1) * sizeof(char));
  if (substring == NULL) {
    return NULL;  // Memory allocation failed
  }

  strncpy(substring, buffer + start, substringLength);
  substring[substringLength] = '\0';

  return substring;
}

sgx_status_t seal_vault(const char* vault, size_t vault_size, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
  return sgx_seal_data(0, NULL, vault_size, (uint8_t*)vault, sealed_size, sealed_data);
}

sgx_status_t unseal(sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len) {
  sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
  return status;
}

sgx_status_t e1_seal_data(char* data, size_t data_size) {
  uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
  uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

  if (sealed_data == NULL) {
    ocall_e1_print_string("Error sealing the vault: Out of memory\n");
    return SGX_ERROR_OUT_OF_MEMORY;
  }

  sgx_status_t sealing_status = seal_vault(data, data_size, (sgx_sealed_data_t*)sealed_data, sealed_size);

  if (sealing_status != 0) {
    free(sealed_data);
    ocall_e1_print_string("Failed to create new vault\n");
    return sealing_status;
  }

  char message[50];
  char* filename = getSubstring(data, 6, 32);

  if(filename == NULL){
    return SGX_ERROR_UNEXPECTED;
  }

  sgx_status_t status = ocall_save_vault(&ret, sealed_data, sealed_size, filename);
  free(sealed_data);
  free(filename);
  if (ret != 0 || status != 0) {
    ocall_e1_print_string("Failed to write the sealed vault to file\n");
    return status;
  }

  snprintf(message, sizeof(message), "Vault successfully created: %u bytes\n\n", sealed_size);

  ocall_e1_print_string(message);
  return SGX_SUCCESS;
}

sgx_status_t e1_unseal_data(uint8_t* sealed_data, size_t sealed_data_size, const char* user_password) {
  char message[5000];

  size_t unsealed_size = sgx_calc_sealed_data_size(0, sealed_data_size);
  uint8_t* unsealed_data = (uint8_t*)malloc(unsealed_size);

  if (unsealed_data == NULL) {
    ocall_e1_print_string("Error unsealing the valut: Out of memory\n");
    return SGX_ERROR_OUT_OF_MEMORY;
  }

  sgx_status_t unsealing_status =
      unseal((sgx_sealed_data_t*)sealed_data, sealed_data_size, unsealed_data, unsealed_size);

  if (unsealing_status != SGX_SUCCESS) {
    snprintf(message, sizeof(message), "Failed to unseal vault: %d\n", unsealing_status);
    ocall_e1_print_string(message);
    return unsealing_status;
  }

  // Calculate the starting position of the password field
  const char* start_ptr = (const char*)(unsealed_data + 38);

  // Create buffer for the vault password (with space for null terminator)
  char vault_password[33] = {0};
  int bytes_printed = 0;
  for (int i = 0; i < 32; i++) {
    bytes_printed +=
        snprintf(vault_password + bytes_printed, sizeof(vault_password) - bytes_printed, "%c", start_ptr[i]);
  }

  if (strcmp(vault_password, user_password) != 0) {
    ocall_e1_print_string("Wrong password, unseal aborted\n");
    free(unsealed_data);
    return SGX_ERROR_UNEXPECTED;
  }

  sgx_status_t status = ocall_load_vault(&ret, unsealed_data, unsealed_size);
	if (ret != 0 || status != 0) {
    free(unsealed_data);
		return SGX_ERROR_UNEXPECTED;
	}

  free(unsealed_data);

  snprintf(message, sizeof(message), "Vault unsealed: %zu bytes\n\n", unsealed_size);
  ocall_e1_print_string(message);

  return SGX_SUCCESS;
}

sgx_status_t e1_update_password(uint8_t* sealed_data, size_t sealed_data_size, const char* user_password, const char* new_password) {
	sgx_status_t status;
	int ocall_ret;
  char message[5000];

	if (new_password == NULL || strlen(new_password) < 1 || strlen(new_password) >= 32) {
    ocall_e1_print_string("Error: Password too long (max 31 characters).\n");
    return SGX_ERROR_UNEXPECTED;
  }

  size_t unsealed_size = sgx_calc_sealed_data_size(0, sealed_data_size);
  uint8_t* unsealed_data = (uint8_t*)malloc(unsealed_size);

  if (unsealed_data == NULL) {
    ocall_e1_print_string("Error unsealing the valut: Out of memory\n");
    return SGX_ERROR_OUT_OF_MEMORY;
  }

  status = unseal((sgx_sealed_data_t*)sealed_data, sealed_data_size, unsealed_data, unsealed_size);

  if (status != SGX_SUCCESS) {
    snprintf(message, sizeof(message), "Failed to unseal vault: %d\n", status);
    ocall_e1_print_string(message);
    return status;
  }

  // Calculate the starting position of the password field
  const char* start_ptr = (const char*)(unsealed_data + 38);

  // Create buffer for the vault password (with space for null terminator)
  char vault_password[33] = {0};
  int bytes_printed = 0;
  for (int i = 0; i < 32; i++) {
    bytes_printed +=
        snprintf(vault_password + bytes_printed, sizeof(vault_password) - bytes_printed, "%c", start_ptr[i]);
  }
  
  ocall_e1_print_string(vault_password);
  ocall_e1_print_string("\n\n");

  if (strcmp(vault_password, user_password) != 0) {
    ocall_e1_print_string("Wrong password, unseal aborted\n");
    free(unsealed_data);
    return SGX_ERROR_UNEXPECTED;
  }

  // Fill the existing password field with null terminators
  memset((char*)start_ptr, '\0', 32); 
  // Update password
  memcpy((char*)start_ptr, new_password, strlen(new_password));

  for (int i = 0; i < 32; i++) {
    bytes_printed +=
        snprintf(vault_password + bytes_printed, sizeof(vault_password) - bytes_printed, "%c", start_ptr[i]);
  }

  uint32_t resealed_size = sgx_calc_sealed_data_size(0, unsealed_size);
  uint8_t* resealed_data = (uint8_t*)malloc(resealed_size);

  status = seal_vault((char*)unsealed_data, unsealed_size, (sgx_sealed_data_t*)resealed_data, resealed_size);

  if (status != 0) {
    free(sealed_data);
    ocall_e1_print_string("Failed to create new vault\n");
    return status;
  }

  char* filename = getSubstring((char *)unsealed_data, 6, 32);

  if(filename == NULL){
    return SGX_ERROR_UNEXPECTED;
  }

  status = ocall_save_vault(&ret, resealed_data, resealed_size, filename);
  free(unsealed_data);
  free(resealed_data);
  free(filename);
  if (ret != 0 || status != 0) {
    ocall_e1_print_string("Failed to write the sealed vault to file\n");
    return status;
  }

  return SGX_SUCCESS;
}

sgx_status_t e1_add_entry(uint8_t* sealed_data, size_t sealed_data_size, char* entry, size_t entry_size, const char* filename, const char* user_password){
  sgx_status_t status;
	int ocall_ret;
  char message[500];

  if(entry_size >= VAULT_ENTRY_SIZE){
    snprintf(message, sizeof(message), "Error: Entry size exceeds maximum allowed.");
    ocall_e1_print_string(message);
    return SGX_ERROR_UNEXPECTED;
  }

  size_t unsealed_size = sgx_calc_sealed_data_size(0, sealed_data_size);
  uint8_t* unsealed_data = (uint8_t*)malloc(unsealed_size);

  if (unsealed_data == NULL) {
    ocall_e1_print_string("Error unsealing the valut: Out of memory\n");
    return SGX_ERROR_OUT_OF_MEMORY;
  }

  status = unseal((sgx_sealed_data_t*)sealed_data, sealed_data_size, unsealed_data, unsealed_size);

  if (status != SGX_SUCCESS) {
    snprintf(message, sizeof(message), "Failed to unseal vault: %d\n", status);
    ocall_e1_print_string(message);
    return status;
  }

  // Calculate the starting position of the password field
  const char* start_ptr = (const char*)(unsealed_data + 38);

  // Create buffer for the vault password (with space for null terminator)
  char vault_password[33] = {0};
  int bytes_printed = 0;
  for (int i = 0; i < 32; i++) {
    bytes_printed +=
        snprintf(vault_password + bytes_printed, sizeof(vault_password) - bytes_printed, "%c", start_ptr[i]);
  }

  if (strcmp(vault_password, user_password) != 0) {
    ocall_e1_print_string("Wrong password, unseal aborted\n");
    free(unsealed_data);
    return SGX_ERROR_UNEXPECTED;
  }

  size_t entry_struct_size = VAULT_ENTRY_SIZE + 32 + sizeof(size_t);

  unsealed_data = (uint8_t *)realloc(unsealed_data, unsealed_size + entry_struct_size);
  if (unsealed_data == NULL) {
    ocall_e1_print_string("Error reallocating memory.\n");
    free(unsealed_data);
    return SGX_ERROR_OUT_OF_MEMORY;
  }

  // Exclude path to file
  char *parsed_filename = strrchr(filename, '/');
  if (parsed_filename == NULL) {
    parsed_filename = (char *)filename;
  } else {
    parsed_filename++;
  }

  int vault_header_size = 110;

  // Vault entry counter
  size_t entry_count = 0;
  memcpy(&entry_count, &unsealed_data[102], sizeof(size_t));

  // Start of new data section
  char* vault_header_end = (char*)(unsealed_data + vault_header_size);
  char* vault_new_data_region = (char*)(vault_header_end + entry_count*entry_struct_size);
  
  // Prevent having two entries with the same name
  for(int i=0; i <= entry_count; i++){
    if (strcmp((char *)(vault_header_end + i*entry_struct_size), parsed_filename) == 0) {
      ocall_e1_print_string("Error: An entry with this name already exists.\n");
      free(unsealed_data);
      return SGX_ERROR_OUT_OF_MEMORY;
    }
  }

  // Write file contents to vault
  size_t offset = 0;
  memcpy(&vault_new_data_region[offset], parsed_filename, strlen(parsed_filename));
  offset += 32;
  memcpy(&vault_new_data_region[offset], entry, entry_size);
  offset += VAULT_ENTRY_SIZE;
  memcpy(&vault_new_data_region[offset], &entry_size, sizeof(entry_size));
  offset += sizeof(size_t);
  memcpy(&vault_new_data_region[offset], entry, sizeof(entry_size));

  // Increase the entry counter and update the counter in the file
  entry_count++;
  memcpy(&unsealed_data[102], &entry_count, sizeof(size_t));
  int raw_vault_size = vault_header_size + entry_count*entry_struct_size;

  uint32_t resealed_size = sgx_calc_sealed_data_size(0, raw_vault_size);
  uint8_t* resealed_data = (uint8_t*)malloc(resealed_size);

  status = seal_vault((char *)unsealed_data, raw_vault_size, (sgx_sealed_data_t*)resealed_data, resealed_size);

  if (status != 0) {
    free(sealed_data);
    ocall_e1_print_string("Failed to seal the vault\n");
    return status;
  }

  char* vault_name = getSubstring((char *)unsealed_data, 6, 32);

  if(vault_name == NULL){
    return SGX_ERROR_UNEXPECTED;
  }

  status = ocall_save_vault(&ret, resealed_data, resealed_size, vault_name);
  free(unsealed_data);
  free(resealed_data);
  free(vault_name);
  if (ret != 0 || status != 0) {
    ocall_e1_print_string("Failed to write the sealed vault to file\n");
    return status;
  }

  return SGX_SUCCESS;
}
