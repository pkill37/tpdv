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

#ifndef _ENCLAVE1_H_
#define _ENCLAVE1_H_

#include <assert.h>
#include <stdlib.h>

#include "sgx_dh.h"
#include "sgx_tseal.h"
#include "../App/Vault.h"

#if defined(__cplusplus)
extern "C" {
#endif

int printf(const char* fmt, ...);
void e1_init_session(sgx_status_t* dh_status);
void e1_process_message1(const sgx_dh_msg1_t* msg1, sgx_dh_msg2_t* msg2, sgx_status_t* dh_status);
void e1_process_message3(const sgx_dh_msg3_t* msg3, sgx_status_t* dh_status);
void e1_show_secret_key(void);
char* getSubstring(const char* buffer, int start, int length);
sgx_status_t seal_vault(const char* vault, size_t vault_size, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t e1_seal_data(char* data, size_t data_size);
sgx_status_t e1_unseal_data(uint8_t* sealed_data, size_t sealed_data_size, const char* user_password);
sgx_status_t e1_update_password(uint8_t* sealed_data, size_t sealed_data_size, const char* user_password, const char* new_password);
sgx_status_t e1_add_item(uint8_t* sealed_data, size_t sealed_data_size, char* entry, size_t entry_size, const char* filename, const char* user_password);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE1_H_ */
