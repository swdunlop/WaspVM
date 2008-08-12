/* Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
 *
 * This library is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU Lesser General Public License, version 2.1
 * as published by the Free Software Foundation.
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
 * for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this library; if not, write to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "waspvm.h"
#include "salsa20.h"

#include <string.h>

WASP_BEGIN_TYPE( salsa20_key );
    salsa20_ctx context;
WASP_END_TYPE( salsa20_key )

#define REQ_SALSA20_KEY_ARG( vn ) REQ_TYPED_ARG( vn, salsa20_key )
#define SALSA20_KEY_RESULT( vn ) TYPED_RESULT( vn, salsa20_key )
#define OPT_SALSA20_KEY_ARG( vn ) OPT_TYPED_ARG( vn, salsa20_key )

WASP_GENERIC_MT( salsa20_key );
WASP_C_TYPE2( salsa20_key, "salsa20-key" );

wasp_salsa20_key wasp_make_salsa20_key( wasp_string seed ){
    int seedlen = wasp_string_length( seed );
    if( seedlen != 32 ) 
        wasp_errf( wasp_es_vm, "si", 
                           "Salsa20 keys must be 32 bytes long", seedlen );
    wasp_salsa20_key key = WASP_OBJALLOC( salsa20_key );

    salsa20_keysetup( & key->context, wasp_sf_string( seed ) );

    return key;
}

void wasp_set_salsa20_iv( wasp_salsa20_key key, wasp_string iv ){
    int ivlen = wasp_string_length( iv );
    if( ivlen != 8 ) 
        wasp_errf( wasp_es_vm, "si", 
                           "Salsa20 IVs must be 8 bytes long", ivlen );
    salsa20_ivsetup( & key->context, wasp_sf_string( iv ) );
}

wasp_string wasp_crypt_salsa20( wasp_salsa20_key key, wasp_string src ){
    int len = wasp_string_length( src );
    wasp_string dst = wasp_make_string( len );

    salsa20_crypt( 
        & key->context, 
        wasp_sf_string( src ), 
        wasp_sf_string( dst ), 
        len 
    );
    
    wasp_string_wrote( dst, len );
    return dst;
}

WASP_BEGIN_PRIM( "make-salsa20-key", make_salsa20_key )
    REQ_STRING_ARG( seed )
    NO_REST_ARGS( );
    
    RESULT( wasp_vf_salsa20_key( wasp_make_salsa20_key( seed ) ) );
WASP_END_PRIM( make_salsa20_key );

WASP_BEGIN_PRIM( "salsa20-encrypt", salsa20_encrypt )
    REQ_SALSA20_KEY_ARG( key );
    REQ_STRING_ARG( plaintext );
    OPT_STRING_ARG( iv );
    NO_REST_ARGS( );
    
    if( has_iv ) wasp_set_salsa20_iv( key, iv );
    RESULT( wasp_vf_string( wasp_crypt_salsa20( key, plaintext ) ) );
WASP_END_PRIM( salsa20_encrypt )

WASP_BEGIN_PRIM( "salsa20-decrypt", salsa20_decrypt )
    REQ_SALSA20_KEY_ARG( key );
    REQ_STRING_ARG( ciphertext );
    OPT_STRING_ARG( iv );
    NO_REST_ARGS( );
    
    if( has_iv ) wasp_set_salsa20_iv( key, iv );
    RESULT( wasp_vf_string( wasp_crypt_salsa20( key, ciphertext ) ) );
WASP_END_PRIM( salsa20_decrypt )

void wasp_init_salsa20_subsystem( ){
    WASP_I_TYPE( salsa20_key );

    WASP_BIND_PRIM( make_salsa20_key )
    WASP_BIND_PRIM( salsa20_encrypt )
    WASP_BIND_PRIM( salsa20_decrypt )
}

