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
    printf("try ocall read nmemb %zu / %zu\n", nmemb, size);
    if (nmemb > 1000000) {
        ocall_fread(ptr, size, 1000000);
        ocall_fread(ptr+1000000*size, size, nmemb-1000000);
    } else {
        ocall_fread(ptr, size, nmemb);
    }
    // ocall_fread(ptr, size, nmemb);
}

void fwrite(void *ptr, size_t size, size_t nmemb, int fp)
{

    ocall_fwrite(ptr, size, nmemb);
}