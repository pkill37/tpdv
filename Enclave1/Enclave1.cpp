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

sgx_status_t status;
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

// show key
void e1_show_secret_key(void) {
  printf("Enclave 1 AEK:");
  for (int i = 0; i < 16; i++) printf(" %02X", 0xFF & (int)e1_aek[i]);
  printf("\n");
}

// Retrieve a substring from a character buffer
char* getSubstring(const char* buffer, int start, int length) {
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

sgx_status_t unseal_vault(const sgx_sealed_data_t* sealed_data, uint8_t* vault, uint32_t vault_size) {
  char message[500];
  snprintf(message, sizeof(message), "I AM HERE: %u\n\n", vault_size);
  ocall_e1_print_string(message);
  return sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)vault, &vault_size);
}

sgx_status_t unseal(sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len) {
  sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
  return status;
}

void e1_seal_data(char* data, size_t data_size) {
  uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
  uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

  sgx_status_t sealing_status = seal_vault(data, data_size, (sgx_sealed_data_t*)sealed_data, sealed_size);

  if (sealing_status != 0) {
    free(sealed_data);
    ocall_e1_print_string("Failed to create new vault\n");
    return;
  }

  char message[50];
  char* filename = getSubstring(data, 6, 32);

  status = ocall_save_vault(&ret, sealed_data, sealed_size, filename);
  free(sealed_data);
  free(filename);
  if (ret != 0 || status != 0) {
    ocall_e1_print_string("Failed to write the sealed vault to file\n");
    return;
  }

  snprintf(message, sizeof(message), "Vault successfully created: %u bytes\n\n", sealed_size);

  ocall_e1_print_string(message);
  return;
}

void e1_unseal_data(uint8_t* sealed_data, size_t sealed_data_size, const char* user_password) {
  char message[5000];

  size_t unsealed_size = sgx_calc_sealed_data_size(0, sealed_data_size);
  uint8_t* unsealed_data = (uint8_t*)malloc(unsealed_size);

  if (unsealed_data == NULL) {
    ocall_e1_print_string("Error unsealing the valut: Out of memory\n");
    return;
  }

  sgx_status_t unsealing_status =
      unseal((sgx_sealed_data_t*)sealed_data, sealed_data_size, unsealed_data, unsealed_size);

  if (unsealing_status == SGX_ERROR_INVALID_PARAMETER) {
    free(sealed_data);
    snprintf(message, sizeof(message), "Failed to unseal vault: %d\n", unsealing_status);
    ocall_e1_print_string(message);
    return;
  }

  /* DEBUG
    const int num_chars_to_print = 32;
    char buffer[num_chars_to_print + 1];
    snprintf(buffer, sizeof(buffer), "%.*s", num_chars_to_print, unsealed_data);
    // Print the result
    snprintf(message, sizeof(message), "First 32 characters: %s\n\n\n", buffer);
    ocall_e1_print_string(message);

    // Calculate the starting position of the password field
    const uint8_t *start_ptr = unsealed_data + 38;
    const char *format_string = "%02x ";
    int bytes_printed = 0;
    // Create buffer with the vault password
    for (int i = 0; i < 32; i++) {
      bytes_printed += snprintf(message + bytes_printed, sizeof(message) -
    bytes_printed, format_string, start_ptr[i]);
    }

    // Ensure string termination (if there's space left)
    if (bytes_printed < sizeof(message) - 1) {
        message[bytes_printed] = '\0';
    }
    ocall_e1_print_string(message);
    ocall_e1_print_string("\n\n");

  */

  ocall_e1_print_string("Unseal success\n");

  // check password
  char* unsealed_data_char = (char*)unsealed_data;
  unsealed_data_char[31] = '\0';

  ocall_e1_print_string("PRINTING RAW DATA: \n\n");

  // Calculate the starting position of the password field
  const char* start_ptr = (const char*)(unsealed_data + 38);

  // Create buffer for the vault password (with space for null terminator)
  char vault_password[33] = {0};
  int bytes_printed = 0;
  for (int i = 0; i < 32; i++) {
    bytes_printed +=
        snprintf(vault_password + bytes_printed, sizeof(vault_password) - bytes_printed, "%c", start_ptr[i]);
  }

  /*
  ocall_e1_print_string(vault_password);
  ocall_e1_print_string("\n\n");
  */

  if (strcmp(vault_password, user_password) != 0) {
    ocall_e1_print_string("Wrong password, unseal aborted\n");
    return;
  }

  snprintf(message, sizeof(message), "Vault unsealed: %zu bytes\n\n", unsealed_size);
  ocall_e1_print_string(message);
}
