#ifndef CHACHA
#define CHACHA

#include "ecrypt-portable.h"

#define CRYPTO_KEYBYTES 32
#define CRYPTO_NONCEBYTES 8

typedef struct
{
  u32 input[16];
} ECRYPT_ctx;


void ECRYPT_keysetup(ECRYPT_ctx *x,const u8 *k,u32 kbits,u32 ivbits);
void ECRYPT_ivsetup(ECRYPT_ctx *x,const u8 *iv);
void ECRYPT_encrypt_bytes(ECRYPT_ctx *x_,const u8 *m,u8 *c_,u32 bytes);
void ECRYPT_decrypt_bytes(ECRYPT_ctx *x,const u8 *c,u8 *m,u32 bytes);

// TODO detect AVX macros?

#endif