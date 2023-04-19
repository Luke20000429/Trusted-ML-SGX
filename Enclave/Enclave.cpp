/*
 * Created on Fri Feb 14 2020
 *
 * Copyright (c) 2020 xxx xxx, xxxx
 */

#include "Enclave.h"
#include "sgx_trts.h"
#include "sgx_thread.h" //for thread manipulation
#include "Enclave_t.h"  /* print_string */
#include <stdarg.h>
#include <stdio.h>
//#include <thread>
#include "sgx_tseal.h"
#include "string.h"

// TODO: store global ptrs instead of return to app
uint8_t *plaintext = NULL;
unsigned plaintext_len = 0, plaintext_ptr = 0;

sgx_status_t seal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
  return sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);
}

sgx_status_t unseal(sgx_sealed_data_t* sealed_data, size_t sealed_size) {
    if (plaintext != NULL) {
        free(plaintext);
        plaintext = NULL;
        plaintext_ptr = 0;
        plaintext_len = 0;
    }
    plaintext_len = sealed_size - sizeof(sgx_sealed_data_t);
    plaintext = (uint8_t*) malloc(plaintext_len);
    return sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*) plaintext, &plaintext_len);
}

void printf(const char *fmt, ...)
{
    PRINT_BLOCK();
}

void sgx_printf(const char *fmt, ...)
{
    PRINT_BLOCK();
}

void empty_ecall()
{
    sgx_printf("Inside empty ecall\n");
}

void fread(void *ptr, size_t size, size_t nmemb, int fp)
{
    // NOTE: fread cannot handle too large file read, split into two parts
    int i = 0;
    for (i = 0; i + 1000000 < nmemb; i = i + 1000000) {
        ocall_fread(ptr, size, 1000000);
        ptr += 1000000*size;
    }
    ocall_fread(ptr, size, nmemb-i);
    ptr += (nmemb-i)*size;
    // TODO: change fread to read from unsealed buffer
    // if (plaintext != NULL && plaintext_ptr < plaintext_len) {
    //     memcpy(ptr, plaintext+plaintext_ptr, nmemb*size);
    //     plaintext_ptr += nmemb*size;
    // } else {
    //     printf("Error: fread failed\n");
    // }
    // if (plaintext_ptr >= plaintext_len) {
    //     free(plaintext);
    //     plaintext = NULL;
    //     plaintext_ptr = 0;
    //     plaintext_len = 0;
    // }
}

void fwrite(void *ptr, size_t size, size_t nmemb, int fp)
{

    ocall_fwrite(ptr, size, nmemb);
}
