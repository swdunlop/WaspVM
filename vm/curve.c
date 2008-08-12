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

#include "curve25519_i64.h"
#include "waspvm.h"

WASP_BEGIN_PRIM( "curve25519-public", curve25519_public )
    REQ_STRING_ARG( private )
    NO_REST_ARGS( )
   
    if( wasp_string_length( private ) != 32 )
        wasp_errf( wasp_es_vm, "si", "private must be 32 bytes long", wasp_string_length( private ) );

    wasp_string public = wasp_make_string( 32 );

    /*
        keygen25519(P, s, k);
	core25519(P, s, k, NULL);
        core25519(Px, s, const k, const Gx);
    */

    keygen25519( 
        wasp_sf_string( public ), 
        NULL,
        wasp_sf_string( private )
    );

    wasp_string_wrote( public, 32 );
    
    STRING_RESULT( public );
WASP_END_PRIM( curve25519_public )

WASP_BEGIN_PRIM( "curve25519-secret", curve25519_secret )
    REQ_STRING_ARG( private )
    REQ_STRING_ARG( public )
    NO_REST_ARGS( );

    if( wasp_string_length( public ) != 32 )
        wasp_errf( wasp_es_vm, "s", "public key must be 32 bytes long" );

    if( wasp_string_length( private ) != 32 )
        wasp_errf( wasp_es_vm, "s", "private key must be 32 bytes long" );
    
    wasp_string s = wasp_make_string( 32 );

    curve25519( wasp_sf_string( s ), 
                wasp_sf_string( private ), 
                wasp_sf_string( public ) );

    wasp_string_wrote( s, 32 );

    STRING_RESULT( s );
WASP_END_PRIM( curve25519_secret )

void wasp_init_curve25519_subsystem( ){
    WASP_BIND_PRIM( curve25519_public );
    WASP_BIND_PRIM( curve25519_secret );
}


