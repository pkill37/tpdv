# TPDV
- Fabio Maia
- Eduardo Monteiro

Tamper-Proof Digital Vault, or TPDV, is a proof of concept for a secure vault Linux application relying on Intel SGX enclaves.

It is designed to offer the following operations: 

- Create a new TPDV file.
- Add a digital asset to the TPDV.
- List all digital assets stored in the TPDV
- Extract one (or perhaps all) digital assets.
- Compare a given message digest with the message digest of a digital asset stored in the TPDV.
- Password change.
- Clone the TPDV contents, perhaps to another version of the TPDV SGX code and to another computer.

## Secure Vault Architecture

First and foremost, we set some boundaries for our security architecture. We consider it noteworthy that SGX's security model does not include secrecy of the code on the host Linux system. Any user on the host Linux system is free to inspect the executable files, as per the ACL and MAC policies of the system of course. With that in mind we relax the preconditions of our security model, and we choose not to spend too much effort in practices against reverse engineering or debugging, of either the application or the enclave software. However, as an illustration of some potential anti-reversing techniques, it could be said that pushing more code inside the enclave perimeter will make dynamic analysis of software more difficult. Indeed there are significant memory safety guarantees that are interesting for critical code paths such as changing the password or adding entries to the vault. Nonetheless, onan SGX enclave is started, the software running in it can be said to be running with interesting isolation properties.

Most critically, it is imperative that the vault file is protected when the data is at rest (not in memory during program execution) which is the textbook use case for Intel SGX. We seal the file when saving from memory to disk, and unseal it when loading from disk to memory. The semantics of sealing ensure that only a given version of the enclave is allowed to process the vault data. It will not be possible to process the vault file outside of the enclave (not even firmware) because the associated key for the encryption and signing is unique to the enclave's lifecycle.

We specify a Diffie-Hellman Key Exchange routine for obtaining a shared key secret with other enclaves. We use AES-GCM encryption with said 128 bit key to secure communication channels between enclaves. This allows the secure implementation of an enclave upgrade or clone feature.

In brief, our architecture stands on top of three important pillars supported by Intel SGX APIs which we will detail more of:

- Isolation
- Sealing
- Diffie-Hellman Key Exchange
- Encryption

### Isolation

For security by isolation purposes, we push to the enclave perimeter the following routines:

1. Data at rest sealing
2. Enclave upgrade  or clone
3. Vault password change
4. Add entry to vault

### Sealing

Sealing data at rest is arguably the most critical security guarantee. In this way only the signer (the enclave) can decrypt the data back, thus limiting the access to the vault to the enclave perimeter. This is accomplished using the `sgx_seal_data` and `sgx_unseal_data` APIs.

### Diffie-Hellman Key Exchange

We use the `sgx_dh_*` SGX API functions to arrive at a shared secret for communication between enclaves.

The Diffie-Hellman key exchange is as follows:

1. Enclave 1 initiates DH session: `sgx_dh_init_session(SGX_DH_SESSION_INITIATOR,&dh_session)`
2. Enclave 2 initiates DH session: `sgx_dh_init_session(SGX_DH_SESSION_RESPONDER,&dh_session)`
3. Enclave 2 creates msg1: `sgx_dh_responder_gen_msg1(sgx_dh_msg1_t *msg1,sgx_dh_session_t *dh_session)`
4. App sends msg1 from Enclave2 to Enclave1
5. Enclave 1 processes msg1: `sgx_dh_initiator_proc_msg1(const sgx_dh_msg1_t *msg1,sgx_dh_msg2_t *msg2,sgx_dh_session_t *dh_session)`
6. App send msg2 from enclave1 to enclave2
7. Enclave 2 processes msg2: `sgx_dh_responder_proc_msg2(const sgx_dh_msg2_t *msg2,sgx_dh_msg3_t *msg3,sgx_dh_session_t *dh_session,sgx_key_128bit_t *aek,sgx_dh_session_enclave_identity_t *initiator_identity)`
8. App sends msg3 from Enclave2 to Enclave1
9. Enclave 1 processes msg3: `sgx_dh_initiator_proc_msg3(const sgx_dh_msg3_t *msg3,sgx_dh_session_t *dh_session,sgx_key_128bit_t *aek,sgx_dh_session_enclave_identity_t *responder_identity)`

### Encryption

For encryption we considered the `sgx_rijndael128GCM_encrypt`, `sgx_rijndael128GCM_decrypt` API below.

```
/**Rijndael AES-GCM - Only 128-bit key AES-GCM Encryption/Decryption is supported
*
* The Galois/Counter Mode (GCM) is a mode of operation of the AES algorithm.
* GCM [NIST SP 800-38D] uses a variation of the Counter mode of operation for encryption.
* GCM assures authenticity of the confidential data (of up to about 64 GB per invocation)
* using a universal hash function defined over a binary finite field (the Galois field).
*
* GCM can also provide authentication assurance for additional data
* (of practically unlimited length per invocation) that is not encrypted.
* GCM provides stronger authentication assurance than a (non-cryptographic) checksum or
* error detecting code. In particular, GCM can detect both accidental modifications of
* the data and intentional, unauthorized modifications.
*
* sgx_rijndael128GCM_encrypt:
* Return: If key, source, destination, MAC, or IV pointer is NULL, SGX_ERROR_INVALID_PARAMETER is returned.
*         If AAD size is > 0 and the AAD pointer is NULL, SGX_ERROR_INVALID_PARAMETER is returned.
*         If the Source Length is < 1, SGX_ERROR_INVALID_PARAMETER is returned.
*         IV Length must = 12 (bytes) or SGX_ERROR_INVALID_PARAMETER is returned.
*         If out of enclave memory then SGX_ERROR_OUT_OF_MEMORY is returned.
*         If the encryption process fails then SGX_ERROR_UNEXPECTED is returned.
*
* sgx_rijndael128GCM_decrypt:
* Return: If key, source, destination, MAC, or IV pointer is NULL, SGX_ERROR_INVALID_PARAMETER is returned.
*         If AAD size is > 0 and the AAD pointer is NULL, SGX_ERROR_INVALID_PARAMETER is returned.
*         If the Source Length is < 1, SGX_ERROR_INVALID_PARAMETER is returned.
*         IV Length must = 12 (bytes) or SGX_ERROR_INVALID_PARAMETER is returned.
*         If the decryption process fails then SGX_ERROR_UNEXPECTED is returned.
*         If the input MAC does not match the calculated MAC, SGX_ERROR_MAC_MISMATCH is returned.
*
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
*   Inputs: sgx_aes_gcm_128bit_key_t *p_key - Pointer to the key used in encryption/decryption operation
*                                             Size MUST BE 128-bits
*           uint8_t *p_src - Pointer to the input stream to be encrypted/decrypted
*           uint32_t src_len - Length of the input stream to be encrypted/decrypted
*           uint8_t *p_iv - Pointer to the initialization vector
*           uint32_t iv_len - Length of the initialization vector - MUST BE 12 (bytes)
*                             NIST AES-GCM recommended IV size = 96 bits
*           uint8_t *p_aad - Pointer to the input stream of additional authentication data
*           uint32_t aad_len - Length of the additional authentication data stream
*           sgx_aes_gcm_128bit_tag_t *p_in_mac - Pointer to the expected MAC in decryption process
*   Output: uint8_t *p_dst - Pointer to the cipher text for encryption or clear text for decryption. Size of buffer should be >= src_len.
*           sgx_aes_gcm_128bit_tag_t *p_out_mac - Pointer to the MAC generated from encryption process
* NOTE: Wrapper is responsible for confirming decryption tag matches encryption tag
*/
sgx_status_t SGXAPI sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *p_key,
                                            const uint8_t *p_src,
                                            uint32_t src_len,
                                            uint8_t *p_dst,
                                            const uint8_t *p_iv,
                                            uint32_t iv_len,
                                            const uint8_t *p_aad,
                                            uint32_t aad_len,
                                            sgx_aes_gcm_128bit_tag_t *p_out_mac);
sgx_status_t SGXAPI sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *p_key,
                                            const uint8_t *p_src,
                                            uint32_t src_len,
                                            uint8_t *p_dst,
                                            const uint8_t *p_iv,
                                            uint32_t iv_len,
                                            const uint8_t *p_aad,
                                            uint32_t aad_len,
                                            const sgx_aes_gcm_128bit_tag_t *p_in_mac);
```

We struggled to work with this API, it was not very clear how to call it. Therefore the clone operation is not fully functional.

## Implementation

In this section we discuss, for each specified feature, our engineering decisions and how they can be used through a simple CLI.

### Create Vault

The following code breakdown explains the process of the creation and sealing of vaults within an SGX enclave.

Code Breakdown:

1. **Vault Creation:**
   - Parses command-line arguments for vault name, password, and author.
   - Validates input for length and potential file conflicts.
   - Creates a `vault_t` object to hold the vault data.

2. **Vault Serialization and Sealing:**

   - Serializes the vault object into a byte array (`serialized_vault`).
   - Calls `e1_seal_data` to seal the serialized vault data within the enclave.

3. **Enclave Sealing (`e1_seal_data`):**

   - Calculates the size needed for the sealed data.
   - Allocates memory for the sealed data.
   - Calls `seal_vault` to perform the actual sealing operation using SGX APIs.
   - Handles errors related to memory allocation or sealing failures.
   - Extracts the filename from the vault data.
   - Saves the sealed vault to a file using `ocall_save_vault`.
   - Frees allocated memory.
   - Prints a success message if the sealing and saving operations are successful.

### Add Entry to Vault

The implementation of this feature within the SGX enclave is a fundamental security decision that prioritizes the integrity of the vault's data. By executing this critical function in a protected, isolated environment, we significantly mitigate the risk of unauthorized modifications or corruption of existing vault data within an untrusted environment.

The enclave-based implementation of `e1_add_entry` directly contributes to:

-   **Data Integrity Assurance:** By preventing unauthorized modifications of the vault's contents during entry addition, we maintain the accuracy and reliability of the stored data.
-   **Resilience Against Attacks:** The enclave's isolation and memory protection mechanisms create a strong barrier against attacks aiming to corrupt or manipulate existing vault entries.

Code Breakdown:

1. **Command-Line Argument Parsing and Validation:**

   - Parses command-line arguments to retrieve the vault name (`filename`), the user-provided password (`user_password`), and the name of the file to be added (`entryname`).
   - Validates the provided password and entry name for correct length and format.
   - Validates that the file to be added is not larger than the max entry size allowed.
   - Reads and parses the contents of the file to be added.

2. **Vault Loading and Unsealing:**

   - Loads the contents of the existing sealed vault from the file.
   - Unseals the vault using the provided password.
   - After unsealing, it compares the given password and the passwod that is stored in the vault, nad ff the password is incorrect, an error message is displayed, and the process terminates.

3. **Entry Addition and Resealing:**

   - The unsealed vault data is reallocated to accommodate the new entry.
   - Checks if an entry with the same name already exists in the vault, returning an error in the affirmative case.
   - The file contents and metadata are added to the vault data.
   - The vault is resealed with the added entry.

4. **Vault Saving:**

   - The resealed vault is saved back to the file system through an ocall (`ocall_save_vault`).
   - If saving fails, an error message is displayed, and the process terminates.

### List Entries in Vault

This feature aims to list the contents of a given sealed vault presenting the entries in chronological order of insertion.

1. **Command-Line Argument Parsing and Validation:**

   - Retrieves the vault name (`filename`) and the user-provided password (`user_password`) from command-line arguments.
   - Validates the password length and format.

2. **Vault Processing and Unsealing:**

   - Calls the `process_vault` function to handle vault loading and unsealing.
   - Frees the memory allocated for the loaded vault (`loaded_vault`).

3. **Vault Unsealing Implementation (`process_vault`):**

   - Loads the sealed vault's contents from the specified file.
   - Calls the `e1_unseal_data` enclave function to unseal the vault using the provided password.

4. **Enclave Unsealing Logic (`e1_unseal_data`):**

   - Calculates the size of the unsealed data and allocates memory.
   - Unseals the vault using the Intel SGX `unseal` function.
   - Extracts and compares the stored password with the user-provided password.
   - If passwords match, loads the unsealed vault, preserving the chronological order of entries.
   - Calls `ocall_load_vault` to load the unsealed vault data into a shared memory location.
   - Returns success or an error status.

If everything is successful, the application prints the contents of the unsealed vault using `vault_print`.

### Get Entry in Vault

The application handles two cases for file extraction:

* **Case 'f': Extract a Single File**
* **Case 'x': Extract All Files**

**Case 'f': Extract a Single File**

1. **Command-Line Argument Handling:**
   - Ensures the user provides enough arguments (`vault_name`, `password`, and `file_name`) when using the `-f` option.
   - Exits with an error message if insufficient arguments are provided.

2. **Input Validation:**
   - Validates the user-provided password and file name:
     - Checks for non-null values.
     - Checks for a valid length (not empty and not exceeding 31 characters).

3. **Vault Processing (process_vault function):**
   - Loads the sealed vault file into memory.
   - Calls the `e1_unseal_data` function to unseal the vault contents using the provided password.
   - If unsealing fails (due to incorrect password or errors), the process terminates.

4. **Vault Entry Retrieval:**
   - Finds the entry with the specified `entryname` within the loaded vault.
   - If the entry isn't found, an error message is displayed, and the process terminates.

5. **Entry Extraction:**
   - If the entry is found, its details (name, data, size) are printed to the console.
   - The `write_vault_entry_data_to_file` function is called to save the extracted entry's data to a file.
   - Success or error messages are displayed based on the outcome of the write operation.

**Vault Unsealing (e1_unseal_data function):**

1. **Memory Allocation and Unsealing:**
   - Calculates the required size for the unsealed data and allocates memory accordingly.
   - Attempts to unseal the sealed vault data using the `unseal` function (provided by Intel SGX).
   - If unsealing fails, an error message is printed, and the function returns an error code.

2. **Password Validation:**
   - Extracts the stored password from the unsealed data.
   - Compares the stored password with the user-provided password.
   - If passwords don't match, an error message is printed, the allocated memory is freed, and the function returns an error code.

3. **Loading the Vault (ocall_load_vault):**
   - Calls the `vault_deserialize` function to deserialize the unsealed vault data into a usable data structure (`loaded_vault`).
   - If deserialization fails, an error message is printed, and the function returns 1.
   - Otherwise, it returns 0 to indicate successful loading.

### Compare Entry Digest in Vault

This feature verifies the integrity of a vault entry using SHA256 hashes. The vault password is checked within the enclave right unsealing, and only if correct, the unsealed data is accessible outside. Checking the password inside the enclave ensures that even if the system is compromised, the password remains encrypted and hidden within the enclave's protected memory. This process leverages SGX's hardware security mechanisms, making it more challenging to extract the password or tamper with the verification process. 

This feature option performs the following functions:

1.  **Validation:** 
    - Verifies and performs basic checks on the command arguments, including vault name, password length, entry name, and the provided hash.
2.  **Process Vault:** 
    - After passing basic validations, the `process_vault()` function is called. This function loads the sealed vault and initiates an ecall to unseal it. If unsealing is successful, the `ocall_load_vault()` is called from within the enclave to deserialize the vault and load it into the global `loaded_vault` variable. (This process is consistent across all operations that don't involve modifying vault data.)
3.  **Entry Verification:** 
    - Once the vault is loaded and deserialized, checks are performed to confirm the existence of the specified entry. If it exists, the hash of the entry is calculated using the `verify_vault_entry_integrity()` function and compared to the hash provided by the user.


### Vault Password Update

This feature allows users to update the password for an existing vault file. Given the sensitivity of vault data and the importance of maintaining its integrity, this operation, like the "add entry" operation, is performed within an SGX enclave. This design choice uses SGX's encrypted memory region to protect the vault contents during the update process, mitigating the risk of unauthorized access or tampering.

**Steps involved:**

1. **Command-Line Arguments and Validation:**
   - The user provides the vault name, current password, and desired new password through command-line arguments.
   - Input validation ensures the passwords meet length and format requirements.

2. **Vault Loading and Unsealing:**
   - The sealed vault is loaded into enclave memory.
   - The vault is unsealed using the current password.
   - The enclave verifies that the provided password matches the stored password, preventing unauthorized changes.

3. **Password Update:**
   - Within the enclave's protected memory space, the existing password field is overwritten with null characters to erase it.
   - The new password is then securely copied into the designated location.

4. **Vault Resealing and Saving:**
   - The modified vault, now containing the updated password, is resealed.
   - An OCALL (`ocall_save_vault`) is used to write the resealed vault back to the file system.


**SGX API Calls**

*   `sgx_calc_sealed_data_size`: Calculates the size of the unsealed vault data.
*   `unseal`: Unseals the vault data using the provided password.
*   `seal_vault`: Seals the vault data with the updated password.

### Clone Vault

Obviously a file sealed by some Enclave1 cannot be accessed by another Enclave2, by definition of what sealing is.  The special feature called the vault clone allows a vault file originally sealed by Enclave1, to be imported to a new enclave Enclave2 which in turn now seals the data.

This is a delicate security engineering task because the two enclaves will have to communicate in order to exchange the contents of the vault. This exchange must be secure, i.e. the vault contents can only be known to Enclave1 and Enclave2. We designed our communication channel to be symmetrically encrypted with AES-GCM using a 128 bit shared key obtained through a Diffie-Hellman key exchange. In this way the contents can be communicated securely because only Enclave1 and Enclave2 will know the key.

This feature was developed as a proof of concept with a few simplifications that allow us to focus on the core study of SGX APIs. For this proof of concept, Enclave1 and Enclave2:

- are both running locally on the same host
- communicate over the Linux filesystem of their host by writing and reading files, protected by standard symmetric encryption
- are identical, except for a version string which exemplifies how to spin off new vault file versions

Under these simplifications this can be considered a case of Local Attestation (rather than Remote Attestation). In practical terms, this could be seen as an upgrade feature that allows upgrading a vault file to be compatible with the latest version of the enclave software.

To securely clone **vault1** (originated from Enclave1) to a new **vault2** (originated by Enclave2) we take the following steps:

1. Through a Diffie-Hellman key exchange, arrive at a shared key secret for secure communication between Enclave1 and Enclave2.
2. Unseal **vault1** through Enclave1 and keep it in host application memory.
3. Encrypt **vault1** with the shared key secret and keep it in host application memory.
4. Send encrypted **vault1** over the communication channel (in this case write a file to the host Linux filesystem).
5. Decrypt **vault1** through Enclave2 and keep it in host application memory.
6. Seal **vault2** through Enclave2 and write it to the new location.

Conceptually the idea is sound but we struggled to make the two enclaves work in parallel. 

## Conclusion

We presented a simple solution for a secure vault software that leverages SGX enclaves to isolate access to the vault file to the perimeter of the enclave software. We developed methodologies for sealing, encryption, and key exchanges using Intel SGX APIs through which we learned how to develop secure applications on the Intel SGX platform.
