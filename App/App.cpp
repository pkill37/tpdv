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

#include "App.h"

#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "Enclave1_u.h"
#include "Enclave2_u.h"
#include "Vault.h"
#include "getopt.h"
#include "sgx_urts.h"
#include "stdint.h"
#include "stdlib.h"

#define APP_NAME "TPDV"
#define APP_VERSION "1.0.0"

vault_t* loaded_vault = NULL;

void hexdump(const void *data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char *)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      printf(" ");
      if ((i + 1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i + 1 == size) {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

/*
 * Error reporting
 */

typedef struct _sgx_errlist_t {
  sgx_status_t error_number;
  const char *message;
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] =
    {/* error list extracted from /opt/intel/sgxsdk/include/sgx_error.h */
     {SGX_SUCCESS, "All is well!"},
     {SGX_ERROR_UNEXPECTED, "Unexpected error"},
     {SGX_ERROR_INVALID_PARAMETER, "The parameter is incorrect"},
     {SGX_ERROR_OUT_OF_MEMORY, "Not enough memory is available to complete this operation"},
     {SGX_ERROR_ENCLAVE_LOST,
      "Enclave lost after power transition or used in "
      "child process created by linux:fork()"},
     {SGX_ERROR_INVALID_STATE, "SGX API is invoked in incorrect order or state"},
     {SGX_ERROR_FEATURE_NOT_SUPPORTED, "Feature is not supported on this platform"},
     {SGX_PTHREAD_EXIT, "Enclave is exited with pthread_exit()"},
     {SGX_ERROR_MEMORY_MAP_FAILURE, "Failed to reserve memory for the enclave"},
     {SGX_ERROR_INVALID_FUNCTION, "The ecall/ocall index is invalid"},
     {SGX_ERROR_OUT_OF_TCS, "The enclave is out of TCS"},
     {SGX_ERROR_ENCLAVE_CRASHED, "The enclave is crashed"},
     {SGX_ERROR_ECALL_NOT_ALLOWED,
      "The ECALL is not allowed at this time, e.g. ecall is blocked by the "
      "dynamic entry table, or nested ecall is not allowed during "
      "initialization"},
     {SGX_ERROR_OCALL_NOT_ALLOWED,
      "The OCALL is not allowed at this time, e.g. ocall is not allowed during "
      "exception handling"},
     {SGX_ERROR_STACK_OVERRUN, "The enclave is running out of stack"},
     {SGX_ERROR_UNDEFINED_SYMBOL, "The enclave image has undefined symbol"},
     {SGX_ERROR_INVALID_ENCLAVE, "The enclave image is not correct"},
     {SGX_ERROR_INVALID_ENCLAVE_ID, "The enclave id is invalid"},
     {SGX_ERROR_INVALID_SIGNATURE, "The signature is invalid"},
     {SGX_ERROR_NDEBUG_ENCLAVE,
      "The enclave is signed as product enclave, and "
      "can not be created as debuggable enclave"},
     {SGX_ERROR_OUT_OF_EPC, "Not enough EPC is available to load the enclave"},
     {SGX_ERROR_NO_DEVICE, "Can't open SGX device"},
     {SGX_ERROR_MEMORY_MAP_CONFLICT, "Page mapping failed in driver"},
     {SGX_ERROR_INVALID_METADATA, "The metadata is incorrect"},
     {SGX_ERROR_DEVICE_BUSY, "Device is busy, mostly EINIT failed"},
     {SGX_ERROR_INVALID_VERSION,
      "Metadata version is inconsistent between uRTS and sgx_sign or uRTS is "
      "incompatible with current platform"},
     {SGX_ERROR_MODE_INCOMPATIBLE,
      "The target enclave 32/64 bit mode or sim/hw mode is incompatible with "
      "the mode of current uRTS"},
     {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file"},
     {SGX_ERROR_INVALID_MISC, "The MiscSelct/MiscMask settings are not correct"},
     {SGX_ERROR_INVALID_LAUNCH_TOKEN, "The launch token is not correct"},
     {SGX_ERROR_MAC_MISMATCH, "Indicates verification error for reports, sealed datas, etc"},
     {SGX_ERROR_INVALID_ATTRIBUTE,
      "The enclave is not authorized, e.g., requesting invalid attribute or "
      "launch key access on legacy SGX platform without FLC"},
     {SGX_ERROR_INVALID_CPUSVN, "The cpu svn is beyond platform's cpu svn value"},
     {SGX_ERROR_INVALID_ISVSVN, "The isv svn is greater than the enclave's isv svn"},
     {SGX_ERROR_INVALID_KEYNAME, "The key name is an unsupported value"},
     {SGX_ERROR_SERVICE_UNAVAILABLE,
      "Indicates aesm didn't respond or the "
      "requested service is not supported"},
     {SGX_ERROR_SERVICE_TIMEOUT, "The request to aesm timed out"},
     {SGX_ERROR_AE_INVALID_EPIDBLOB, "Indicates epid blob verification error"},
     {SGX_ERROR_SERVICE_INVALID_PRIVILEGE,
      " Enclave not authorized to run, .e.g. provisioning enclave hosted in an "
      "app without access rights to /dev/sgx_provision"},
     {SGX_ERROR_EPID_MEMBER_REVOKED, "The EPID group membership is revoked"},
     {SGX_ERROR_UPDATE_NEEDED, "SGX needs to be updated"},
     {SGX_ERROR_NETWORK_FAILURE, "Network connecting or proxy setting issue is encountered"},
     {SGX_ERROR_AE_SESSION_INVALID, "Session is invalid or ended by server"},
     {SGX_ERROR_BUSY, "The requested service is temporarily not available"},
     {SGX_ERROR_MC_NOT_FOUND, "The Monotonic Counter doesn't exist or has been invalided"},
     {SGX_ERROR_MC_NO_ACCESS_RIGHT, "Caller doesn't have the access right to specified VMC"},
     {SGX_ERROR_MC_USED_UP, "Monotonic counters are used out"},
     {SGX_ERROR_MC_OVER_QUOTA, "Monotonic counters exceeds quota limitation"},
     {SGX_ERROR_KDF_MISMATCH, "Key derivation function doesn't match during key exchange"},
     {SGX_ERROR_UNRECOGNIZED_PLATFORM,
      "EPID Provisioning failed due to platform not recognized by backend "
      "server"},
     {SGX_ERROR_UNSUPPORTED_CONFIG,
      "The config for trigging EPID Provisiong "
      "or PSE Provisiong&LTP is invalid"},
     {SGX_ERROR_NO_PRIVILEGE, "Not enough privilege to perform the operation"},
     {SGX_ERROR_PCL_ENCRYPTED, "trying to encrypt an already encrypted enclave"},
     {SGX_ERROR_PCL_NOT_ENCRYPTED, "trying to load a plain enclave using sgx_create_encrypted_enclave"},
     {SGX_ERROR_PCL_MAC_MISMATCH, "section mac result does not match build time mac"},
     {SGX_ERROR_PCL_SHA_MISMATCH, "Unsealed key MAC does not match MAC of key hardcoded in enclave binary"},
     {SGX_ERROR_PCL_GUID_MISMATCH, "GUID in sealed blob does not match GUID hardcoded in enclave binary"},
     {SGX_ERROR_FILE_BAD_STATUS, "The file is in bad status, run sgx_clearerr to try and fix it"},
     {SGX_ERROR_FILE_NO_KEY_ID, "The Key ID field is all zeros, can't re-generate the encryption key"},
     {SGX_ERROR_FILE_NAME_MISMATCH,
      "The current file name is different then the original file name (not "
      "allowed, substitution attack)"},
     {SGX_ERROR_FILE_NOT_SGX_FILE, "The file is not an SGX file"},
     {SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE,
      "A recovery file can't be opened, so flush operation can't continue "
      "(only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE,
      "A recovery file can't be written, so flush operation can't continue "
      "(only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_RECOVERY_NEEDED,
      "When openeing the file, recovery is needed, but the recovery process "
      "failed"},
     {SGX_ERROR_FILE_FLUSH_FAILED, "fflush operation (to disk) failed (only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_CLOSE_FAILED, "fclose operation (to disk) failed (only used when no EXXX is returned)"},
     {SGX_ERROR_UNSUPPORTED_ATT_KEY_ID, "platform quoting infrastructure does not support the key"},
     {SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE, "Failed to generate and certify the attestation key"},
     {SGX_ERROR_ATT_KEY_UNINITIALIZED,
      "The platform quoting infrastructure does not have the attestation key "
      "available to generate quote"},
     {SGX_ERROR_INVALID_ATT_KEY_CERT_DATA,
      "TThe data returned by the platform library's sgx_get_quote_config() is "
      "invalid"},
     {SGX_ERROR_PLATFORM_CERT_UNAVAILABLE, "The PCK Cert for the platform is not available"},
     {SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, "The ioctl for enclave_create unexpectedly failed with EINTR"}};

void print_error_message(sgx_status_t ret, const char *sgx_function_name) {
  size_t ttl = sizeof(sgx_errlist) / sizeof(sgx_errlist[0]);
  size_t idx;

  if (sgx_function_name != NULL) printf("Function: %s\n", sgx_function_name);
  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].error_number) {
      printf("Error: %s\n", sgx_errlist[idx].message);
      break;
    }
  }
  if (idx == ttl)
    printf(
        "Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer "
        "Reference\" for more details.\n",
        ret);
}

/*
 * Enclave1 stuff
 */

sgx_enclave_id_t global_eid1 = 0;

int initialize_enclave1(void) {
  sgx_status_t ret;

  if ((ret = sgx_create_enclave(ENCLAVE1_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid1, NULL)) != SGX_SUCCESS) {
    print_error_message(ret, "sgx_create_enclave (enclave1)");
    return -1;
  }
  return 0;
}

void ocall_e1_print_string(const char *str) { printf("%s", str); }

/*
 * Enclave2 stuff
 */

sgx_enclave_id_t global_eid2 = 0;

int initialize_enclave2(void) {
  sgx_status_t ret;

  if ((ret = sgx_create_enclave(ENCLAVE2_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid2, NULL)) != SGX_SUCCESS) {
    print_error_message(ret, "sgx_create_enclave (enclave2)");
    return -1;
  }
  return 0;
}

void ocall_e2_print_string(const char *str) { printf("%s", str); }

int ocall_save_vault(const uint8_t *sealed_data, const size_t sealed_size, const char *filename) {
  FILE *file = fopen(filename, "wb");
  if (file == NULL) {
    perror("Error opening file");
    return 1;
  }

  size_t elements_written = fwrite((const char *)sealed_data, sizeof(char), sealed_size, file);
  if (elements_written != sealed_size) {
    perror("Error writing to file");
    fclose(file);
    return 1;
  }
  
  fclose(file);
  return 0;
}

int ocall_load_vault(uint8_t *unsealed_data, const size_t unsealed_size) {
  loaded_vault = vault_deserialize(unsealed_data,unsealed_size);
  if(loaded_vault == NULL){
    printf("Vault deserialization failed\n");
    return 1;
  }
  //printf("\n\nDESERIALIZED VAULT: last entry: %s - data: %s\n\n",loaded_vault->head->name,loaded_vault->head->data);
  return 0;
}

void print_help() {
    printf("Usage: <program_name> [options]\n");
    printf("Options:\n");
    printf("-h\t\tShow help menu\n");
    printf("-d <vault_name> <password> <digest>\tCompare digest with file in vault\n");
    printf("-x <vault_name> <password>\t\tExtract all files from vault\n");
    printf("-f <vault_name> <password> <file_name>\tExtract file from vault\n");
    printf("-v <vault_name> <password> <author>\tCreate a new vault\n");
    printf("-a <vault_name> <password> <file_name>\tAdd file to vault\n");
    printf("-l <vault_name> <password>\t\tList all files in vault\n");
    printf("-p <vault_name> <curr_password> <new_password>\tChange vault password\n");
    printf("-c <vault_name> <password> <vault2_name>\tClone vault contents\n");
}

/*
 * Application entry
 */

int SGX_CDECL main(int argc, char *argv[]) {
  sgx_status_t ret, dh_status, ecall_status;
  sgx_dh_msg1_t msg1;
  sgx_dh_msg2_t msg2;
  sgx_dh_msg3_t msg3;

  // create enclaves
  if (initialize_enclave1() < 0) return 1;
  if (initialize_enclave2() < 0) return 2;

  /* DH key establishment between the two enclaves */
  /* step 1 */
  if ((ret = e1_init_session(global_eid1, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
    print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "e1_init_session");
    return 1;
  }
  
  // New entry point

  int opt;
  const char *options = "hdxfvalpc";

  if(argc < 2){
    print_help();
    return 0;
  }

  // read user input
  while ((opt = getopt(argc, argv, options)) != -1) {
    switch (opt) {
      // Show help info
      case 'h':
        print_help();
        break;

      // Compare the provided digest with the digest from a file in the vault
      case 'd':
        if (optind + 2 >= argc) {
          printf("Error: Insufficient arguments for option -d\n");
          printf("-d <vault_name> <password> <digest>\tCompare digest with file in vault\n");
          exit(EXIT_FAILURE);
        }
        printf("Option d - Comparing digest with file in vault\n");
        // Compare the digest with file in vault

        //check if file exists
        //check if it is a valid sealed file
        //load contents into memory
        //copy code from below

        break;

      // Extract all files from the vault
      case 'x':
        if (optind + 1 >= argc) {
          printf("Error: Insufficient arguments for option -x\n");
          printf("-d <vault_name> <password> <digest>\tCompare digest with file in vault\n");
          exit(EXIT_FAILURE);
        }
        printf("Option x - Extracting all files from vault\n");
        // Extract all files from vault
        break;

      // Extract 1 file from the vault
      case 'f':
        if (optind + 2 >= argc) {
          printf("Error: Insufficient arguments for option -f\n");
          printf("-f <vault_name> <password> <file_name>\tExtract file from vault\n");
          exit(EXIT_FAILURE);
        }
        printf("Option f - Extracting file from vault\n");
        // Extract file from vault
        break;

      // Create a vault
      case 'v':
        if (optind + 2 >= argc) {
          printf("Error: Insufficient arguments for option -v\n");
          printf("-v <vault_name> <password> <author>\tCreate a new vault\n");
          exit(EXIT_FAILURE);
        }
        printf("Option v - Creating a new vault\n");
        // Create a new vault
        break;

      // Add item to the vault
      case 'a':
        if (optind + 2 >= argc) {
          printf("Error: Insufficient arguments for option -a\n");
          printf("-a <vault_name> <password> <file_name>\tAdd file to vault\n");
          exit(EXIT_FAILURE);
        }
        printf("Option a - Adding file to vault\n");
        // Add file to vault
        break;

      // List all files from the vault
      case 'l':{
        if (optind + 1 >= argc) {
          printf("Error: Insufficient arguments for option -l\n");
          printf("-l <vault_name> <password>\t\tList all files in vault\n");
          exit(EXIT_FAILURE);
        }

        const char* user_password = argv[3];
        const char* filename = argv[2];
        if (user_password == NULL || strlen(user_password) < 1 || strlen(user_password) >= 32) {
          printf("Invalid password\n");
          exit(EXIT_FAILURE);
        }

        // Read vault file
        size_t file_size;
        uint8_t *vault_file_contents = load_vault_contents(filename, &file_size);

        if (vault_file_contents == NULL) {
          fprintf(stderr, "Error: Unable to open vault file '%s'.",filename);
          exit(EXIT_FAILURE);
        }

        printf("File loaded successfully!\n");
        printf("File size: %zu bytes\n", file_size);

        // Unseal vault
        e1_unseal_data(global_eid1, &ret, vault_file_contents, file_size, user_password);
        if (ret != SGX_SUCCESS) {
          fprintf(stderr, "Error: Failed to unseal vault data.\n");
          free(vault_file_contents);
          exit(EXIT_FAILURE);
        }
          
        vault_print(loaded_vault);

        free(loaded_vault);
        free(vault_file_contents);
        
        break;
      }

      // Change vault password
      case 'p':{
        if (optind + 2 >= argc) {
          printf("Error: Insufficient arguments for option -p\n");
          printf("-p <vault_name> <curr_password> <new_password>\tChange vault password\n");
          exit(EXIT_FAILURE);
        }
        printf("Option p - Changing vault password\n");
        // Change vault password
        const char* user_password = argv[3];
        const char* new_user_password = argv[4];
        const char* filename = argv[2];
        if (user_password == NULL || strlen(user_password) < 1 || strlen(user_password) >= 32) {
          printf("Invalid password\n");
          exit(EXIT_FAILURE);
        }

        if (new_user_password == NULL || strlen(new_user_password) < 1 || strlen(new_user_password) >= 32) {
          fprintf(stderr, "Error: Password too long (max 31 characters).\n");
          exit(EXIT_FAILURE);
        }

        // Read vault file
        size_t file_size;
        uint8_t *vault_file_contents = load_vault_contents(filename, &file_size);

        if (vault_file_contents == NULL) {
          fprintf(stderr, "Error: Unable to open vault file '%s'.\n",filename);
          exit(EXIT_FAILURE);
        }

        printf("File loaded successfully!\n");
        printf("File size: %zu bytes\n", file_size);
        
        // Unseal vault
        ecall_status = e1_unseal_data(global_eid1, &ret, vault_file_contents, file_size, user_password);
        if (ecall_status != SGX_SUCCESS || ret != SGX_SUCCESS) {
          fprintf(stderr, "Error: Failed to unseal vault data.\n");
          free(vault_file_contents);
          exit(EXIT_FAILURE);
        }
        
        loaded_vault = vault_change_password(loaded_vault, new_user_password);
        
        // Prepare and seal vault data for storage
        char serialized_vault[vault_total_size(loaded_vault)];
        size_t serialized_vault_size = vault_serialize(loaded_vault, serialized_vault);

        ecall_status = e1_seal_data(global_eid1, &ret, serialized_vault, serialized_vault_size);
        if (ecall_status != SGX_SUCCESS || ret != SGX_SUCCESS) {
          fprintf(stderr, "Error: Failed to seal vault data.\n");
          free(vault_file_contents);
          exit(EXIT_FAILURE);
        }

        printf("Password updated successfully.\n");

        free(loaded_vault);
        free(vault_file_contents);

        break;
      }

      // Clone vault contents
      case 'c':
        if (optind + 1 >= argc) {
          printf("Error: Insufficient arguments for option -c\n");
          printf("-c <vault_name> <password> <vault2_name>\tClone vault contents\n");
          exit(EXIT_FAILURE);
        }
        printf("Option c - Cloning vault contents\n");
        // Clone vault contents
        break;

      default:
        printf("Unknown option\n");
        print_help();
        exit(EXIT_FAILURE);
    }
  }

  return 0;

  // Create a new vault
  // Read from input
  char user_password[] = "password";
  vault_t *vault = vault_new("vault.dat", user_password, "author");

  vault_print(vault);
  if (vault_authenticate(vault, user_password)) {
    printf("Authenticated\n");
    // Add a new entry
    vault = vault_add(vault, "entry1", "data1");
    vault = vault_add(vault, "entry2", "data2");
    vault_print(vault);

    //serialize vault with data and seal it
    char serialized_vault[vault_total_size(vault)];
    size_t serialized_vault_size = vault_serialize(vault, serialized_vault);
    e1_seal_data(global_eid1, &ret, serialized_vault, serialized_vault_size);

    // wait for vault to be unsealed and serialize Vault object -
    // ocall_save_vault
    //  List all entries
    vault_entry_t *entry = vault->head;
    while (entry != NULL) {
      vault_entry_print(entry);
      entry = entry->next;
    }

    // Read sealed vault data
    FILE *fp = fopen("vault.dat", "rb");
    if (fp == NULL) {
      perror("fopen");
      return 1;
    }

    // Get the file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size == -1) {
      perror("ftell");
      fclose(fp);
      return 1;
    }
    rewind(fp);  // Reset the file position to the beginning

    uint8_t *buffer = (uint8_t *)malloc(file_size);
    if (buffer == NULL) {
      fprintf(stderr, "Memory allocation failed.\n");
      fclose(fp);
      return 1;
    }

    // hexdump(buffer,file_size);

    // Read the file contents
    size_t bytes_read = fread(buffer, 1, file_size, fp);
    if (bytes_read != file_size) {
      fprintf(stderr, "Error reading file.\n");
      free(buffer);
      fclose(fp);
      return 1;
    }

    size_t sealed_data_size = file_size;

    // Print the file size
    printf("File size: %zu bytes\n", sealed_data_size);

    // Unseal vault with data - only unseals 8 bytes for some reason
    e1_unseal_data(global_eid1, &ret, buffer, sealed_data_size, user_password);

    // Clean up
    free(buffer);
    fclose(fp);

    // DH to exchange keys - and transfer the vault from enclave1 to enclave1
    // using uint8_t* (or other suitable data structure)

    // Extract entry
    if (argc == 3 && strcmp(argv[1], "-x") == 0) {
      vault_entry_t *entry_to_extract = vault_get_entry_by_name(vault, argv[2]);

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
    strncpy(user_password, "newpassword", sizeof(user_password) - 1);
    user_password[sizeof(user_password) - 1] = '\0';
    vault = vault_change_password(vault, user_password);
    vault_print(vault);

    // Compare digest - test case
    if (argc == 4 && strcmp(argv[1], "-d") == 0) {
      size_t user_digest_length = strlen(argv[3]);
      if (user_digest_length != SHA256_DIGEST_SIZE * 2) {
        printf("Invalid input: SHA-256 digest must be %d characters long\n", SHA256_DIGEST_SIZE * 2);
        return 1;
      }

      vault_entry_t *entry_to_digest = vault_get_entry_by_name(vault, argv[2]);

      if (entry_to_digest != NULL) {
        printf("Found entry:\n");
        printf(" Name: %s\n", entry_to_digest->name);
        printf(" Data: %s\n", entry_to_digest->data);
        printf(" Size: %zu\n", entry_to_digest->size);
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

  vault_free(vault);

  /* step 2 */
  if ((ret = e2_init_session(global_eid2, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
    print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "e2_init_session");
    return 1;
  }
  /* step 3 */
  if ((ret = e2_create_message1(global_eid2, &msg1, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
    print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "e2_create_message1");
    return 1;
  }
  /* step 4 */
  /* step 5 */
  if ((ret = e1_process_message1(global_eid1, &msg1, &msg2, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
    print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "e1_process_message1");
    return 1;
  }
  /* step 6 */
  /* step 7 */
  if ((ret = e2_process_message2(global_eid2, &msg2, &msg3, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
    print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "e2_process_message2");
    return 1;
  }
  /* step 8 */
  /* step 9 */
  if ((ret = e1_process_message3(global_eid1, &msg3, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS) {
    print_error_message((ret != SGX_SUCCESS) ? ret : dh_status, "e1_process_message3");
    return 1;
  }
  /* done! show secret key */
  if ((ret = e1_show_secret_key(global_eid1)) != SGX_SUCCESS) {
    print_error_message(ret, "e1_show_secret_key");
    return 1;
  }
  if ((ret = e2_show_secret_key(global_eid2)) != SGX_SUCCESS) {
    print_error_message(ret, "e2_show_secret_key");
    return 1;
  }
  /* destroy enclaves */
  if ((ret = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS) {
    print_error_message(ret, "sgx_destroy_enclave (enclave1)");
    return 1;
  }
  if ((ret = sgx_destroy_enclave(global_eid2)) != SGX_SUCCESS) {
    print_error_message(ret, "sgx_destroy_enclave (enclave2)");
    return 1;
  }

  return 0;
}
