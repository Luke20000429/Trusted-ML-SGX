#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "string.h"
#include "enclave_t.h"

// TODO: store global ptrs instead of return to app

sgx_status_t seal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
  return sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);
}

sgx_status_t unseal(sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len) {
  return sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*) plaintext, &plaintext_len);
}
