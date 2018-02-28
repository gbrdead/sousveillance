#ifndef __CTF_PTOOIE_ROT13_H__
#define __CTF_PTOOIE_ROT13_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif


#define ENCRYPTED_STRING_MAX_SIZE 128

struct EncryptedString
{
    uint64_t prngSeed;
    char str[ENCRYPTED_STRING_MAX_SIZE];
};

uint64_t xorshift64star(uint64_t* state);
void decryptString(const struct EncryptedString* encStr, char decryptedStr[ENCRYPTED_STRING_MAX_SIZE]);


#ifdef __cplusplus
}
#endif

#endif
