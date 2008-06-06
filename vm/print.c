/* Copyright (C) 2006, Ephemeral Security, LLC 
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void wasp_printmem( const void* mem, wasp_integer len ){
    while( len ){
       int rs = write( STDOUT_FILENO, mem, len );
       if( rs > 0 ){
          len -= rs;
       }else if( rs ){ break; }
    }
}
void wasp_print( const char* st ){
    wasp_printmem( st, strlen( st ) );
}
void wasp_printch( wasp_byte ch ){
    wasp_printmem( &ch, 1 );
}
void wasp_printstr( wasp_string s ){
    if( s )wasp_print( wasp_sf_string( s ) );
}
void wasp_newline( ){
    wasp_printch( '\n' );
}
void wasp_space( ){
    wasp_printch( ' ' );
}
void wasp_show( wasp_value v ){
    wasp_string s = wasp_make_string( 64 );
    wasp_format_value( s, v, 32, 16 );
    wasp_printstr( s );
    wasp_objfree( s );
}

WASP_BEGIN_PRIM( "print", print )
    REQ_STRING_ARG( value );
    NO_REST_ARGS( );
    
    wasp_printstr( value );

    NO_RESULT( );
WASP_END_PRIM( print )

WASP_BEGIN_PRIM( "format", format )
    REQ_ANY_ARG( value );
    OPT_INTEGER_ARG( breadth );
    OPT_INTEGER_ARG( depth );
    OPT_STRING_ARG( buffer );
    NO_REST_ARGS( );
    
    if( ! has_buffer ) buffer = wasp_make_string( 64 );
    if( ! has_breadth ) breadth = 32;
    if( ! has_depth ) depth = 3;

    wasp_format_value( buffer, value, breadth, depth );

    STRING_RESULT( buffer );
WASP_END_PRIM( format )

void wasp_init_print_subsystem( ){
    WASP_BIND_PRIM( print );
    WASP_BIND_PRIM( format );
}
