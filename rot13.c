#include "rot13.h"

#include <string.h>


// Shamelessly copied from: https://en.wikipedia.org/wiki/Xorshift#xorshift*
uint64_t xorshift64star(uint64_t* state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1D;
}

void decryptString(const struct EncryptedString* encStr, char decryptedStr[ENCRYPTED_STRING_MAX_SIZE])
{
    uint64_t prngState = encStr->prngSeed;
    memcpy(decryptedStr, encStr->str, ENCRYPTED_STRING_MAX_SIZE * sizeof(char));

    const char* decryptedStrEnd = decryptedStr + ENCRYPTED_STRING_MAX_SIZE;
    for (char* c = decryptedStr; c < decryptedStrEnd; c++)
    {
        char randomValue = xorshift64star(&prngState);
        *c -=  randomValue;
    }
}
