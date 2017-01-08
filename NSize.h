#ifndef N_SIZE_H
#define N_SIZE_H

#include <stdint.h>

int nSizeEncrypt(uint8_t* message, uint8_t* out, uint32_t size, uint8_t * key, uint32_t keysize, uint8_t * iv, uint32_t ivsize);

int nSizeDecrypt(uint8_t* message, uint8_t* out, uint32_t size, uint8_t * key, uint32_t keysize, uint8_t * iv, uint32_t ivsize);

#endif