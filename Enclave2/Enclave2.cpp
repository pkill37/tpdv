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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave2.h"
#include "Enclave2_t.h"  /* e1_print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char *fmt, ...)
{
  char buf[BUFSIZ] = { '\0' };
  va_list ap;

  va_start(ap,fmt);
  (void)vsnprintf(buf,BUFSIZ,fmt, ap);
  va_end(ap);
  ocall_e2_print_string(buf);
  return 0;
}


/*
 * ECALL (it just prints a string)
 */

void e2_printf_hello_world(void)
{
  printf("Hello from enclave 2\n");
}


/*
 * DH key exchange data (4 more ECALLs)
 */

static sgx_dh_session_t e2_session;
static sgx_key_128bit_t e2_aek;
static sgx_dh_session_enclave_identity_t e2_initiator_identity;

// step 2
void e2_init_session(sgx_status_t *dh_status)
{
  *dh_status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER,&e2_session);
}

// step 3
void e2_create_message1(sgx_dh_msg1_t *msg1,sgx_status_t *dh_status)
{
  *dh_status = sgx_dh_responder_gen_msg1(msg1,&e2_session);
}

// step 7
void e2_process_message2(const sgx_dh_msg2_t *msg2,sgx_dh_msg3_t *msg3,sgx_status_t *dh_status)
{
  *dh_status = sgx_dh_responder_proc_msg2(msg2,msg3,&e2_session,&e2_aek,&e2_initiator_identity);
}

// show key
void e2_show_secret_key(void)
{
  printf("Enclave 2 AEK:");
  for(int i = 0;i < 16;i++)
    printf(" %02X",0xFF & (int)e2_aek[i]);
  printf("\n");
}
