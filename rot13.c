#include "rot13.h"

void rot13(char* str)
{
    for (char* c = str; *c != '\0'; c++)
    {
        if (*c >= 'A'  &&  *c <= 'Z')
        {
            if (*c + 13 <= 'Z')
            {
                *c += 13;
            }
            else
            {
                *c -= 13;
            }
        }
        else if (*c >= 'a'  &&  *c <= 'z')
        {
            if (*c + 13 <= 'z')
            {
                *c += 13;
            }
            else
            {
                *c -= 13;
            }
        }
    }
}
