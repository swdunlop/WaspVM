/* salsa20-sync.h
 * Heavily modified from the ECRYPT header for Salsa20. */

#ifndef SALSA20_SYNC
#define SALSA20_SYNC

#include "salsa20-portable.h"


// The Salsa20 Cipher Context
typedef struct{ u32 input[16]; }salsa20_ctx;

/* ------------------------------------------------------------------------- */

void salsa20_keysetup( salsa20_ctx* ctx, const u8* key );
void salsa20_ivsetup( salsa20_ctx* ctx, const u8* iv);
void salsa20_crypt( 
    salsa20_ctx* ctx, const u8* src, u8* dst, u32 len 
);                

#endif
