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

WASP_BEGIN_TYPE( salsa20_key )
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
    OPT_STRING_ARG( iv )
    NO_REST_ARGS( );

    wasp_salsa20_key key = wasp_make_salsa20_key( seed );
    if( has_iv ) wasp_set_salsa20_iv( key, iv );
    
    RESULT( wasp_vf_salsa20_key( key ) );
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

#ifdef WASP_IN_WIN32
#include <wincrypt.h>

HCRYPTPROV wasp_random_context = 0;

int wasp_get_random_context( ){
    if( wasp_random_context ) return wasp_random_context;
    
    if( CryptAcquireContext( 
        & wasp_random_context, NULL, NULL, PROV_RSA_FULL, 
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT
    ) ){
        return wasp_random_context;
    }
    
    wasp_raise_winerror( wasp_es_vm );
    // wasp_errf( wasp_es_vm, "s", "could not acquire CryptApi context" );
    return 0;
}

void wasp_read_entropy( void* ptr, int req ){
    wasp_string entropy = wasp_make_string( req );
    
    if( ! CryptGenRandom( wasp_get_random_context( ), req, ptr ) ){
        wasp_raise_winerror( wasp_es_vm );
        //wasp_errf( wasp_es_vm, "s", "could not access entropy from CryptApi" );
    }
}

#else

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int wasp_random_handle = 0;

int wasp_get_random_handle( ){
    if( wasp_random_handle ) return wasp_random_handle;

    wasp_random_handle = open( "/dev/urandom", O_RDONLY );
    if( wasp_random_handle > 0 ) return wasp_random_handle;
    
    wasp_random_handle = open( "/dev/random", O_RDONLY );
    if( wasp_random_handle > 0 ) return wasp_random_handle;

    wasp_random_handle = 0;
    wasp_errf( wasp_es_vm, "s", "could not open OS entropy source" );
    return 0;
}

void wasp_read_entropy( void* ptr, int req ){
    while( req ){
        int amt = wasp_os_error( read( wasp_get_random_handle( ), ptr, req ) );
        req -= amt;
        ptr += amt;
    };
}

#endif

wasp_string wasp_read_entropy_str( int req ){
    wasp_string entropy = wasp_make_string( req );
    wasp_read_entropy( wasp_sf_string( entropy ), req );
    wasp_string_wrote( entropy, req );
    return entropy;
}

WASP_BEGIN_PRIM( "read-entropy", read_entropy )
    REQ_INTEGER_ARG( amount );
    NO_REST_ARGS( );
    
    STRING_RESULT( wasp_read_entropy_str( amount ) );
WASP_END_PRIM( read_entropy )

wasp_salsa20_key wasp_prng = NULL;

wasp_salsa20_key wasp_get_prng( ){
    if( wasp_prng ) return wasp_prng;
    wasp_string seed = wasp_read_entropy_str( 32 );
    wasp_string iv = wasp_read_entropy_str( 8 );

    wasp_prng = wasp_make_salsa20_key( seed );
    wasp_root_obj( (wasp_object) wasp_prng );
    wasp_set_salsa20_iv( wasp_prng, iv );

    return wasp_prng;
}

wasp_string wasp_read_prng( int req ){
    wasp_string data = wasp_make_string( req );
    salsa20_crypt( 
        & wasp_get_prng( )->context, 
        wasp_sf_string( data ), 
        wasp_sf_string( data ), 
       req  
    );
    
    wasp_string_wrote( data, req );
    return data;
}

wasp_quad wasp_random_quad( ){
    char q[sizeof(wasp_quad)] = { 0 };
    salsa20_crypt( 
        & wasp_get_prng( )->context, 
        q, q, sizeof(wasp_quad)
    );
    return *(wasp_quad*)q; 
}

wasp_integer wasp_random_integer( wasp_integer min, wasp_integer max ){
    if( min > max ){ int temp = max; max = min; min = temp; };
    wasp_quad base = max - min;
    if( base == 0 ) return min;
    if( base == 0xFFFFFFFF ) return (wasp_integer) wasp_random_quad( );
    base ++;
    wasp_quad maxrnd = 
        (wasp_quad)( ( 0x100000000ull ) / base * base - 1 );

    wasp_quad rnd;

    for(;;){ 
        rnd = wasp_random_quad( ); 
        if( rnd <= maxrnd ) break; 
    }

    return min + rnd % base;
}

WASP_BEGIN_PRIM( "random-integer", random_integer )
    REQ_INTEGER_ARG( min );
    REQ_INTEGER_ARG( max );
    
    INTEGER_RESULT( wasp_random_integer( min, max ) );
WASP_END_PRIM( random_integer )

WASP_BEGIN_PRIM( "read-prng", read_prng )
    REQ_INTEGER_ARG( amount );
    NO_REST_ARGS( );
    
    STRING_RESULT( wasp_read_prng( amount ) );
WASP_END_PRIM( read_prng );

void wasp_init_salsa20_subsystem( ){
    WASP_I_TYPE( salsa20_key );

    WASP_BIND_PRIM( make_salsa20_key )
    WASP_BIND_PRIM( salsa20_encrypt )
    WASP_BIND_PRIM( salsa20_decrypt )
    WASP_BIND_PRIM( read_entropy )
    WASP_BIND_PRIM( read_prng )
    WASP_BIND_PRIM( random_integer )
}

