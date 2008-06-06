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

void wasp_format_number( wasp_string buf, wasp_value v ){
    wasp_string_append_signed( buf, wasp_integer_fv( v ) );
}

wasp_integer wasp_number_compare( wasp_value a, wasp_value b ){
    return wasp_integer_fv( a ) - wasp_integer_fv( b );
}

WASP_GENERIC_GC( number );
WASP_C_TYPE( number );

wasp_number wasp_nf_integer( wasp_integer x ){
    wasp_number io = WASP_OBJALLOC( number );
    io->intval = x;
    return io;
}
wasp_integer wasp_integer_fn( wasp_number x ){
    return x->intval;
}
wasp_integer wasp_integer_fv( wasp_value x ){
    assert( wasp_is_number( x ) || wasp_is_imm( x ) );

    if( wasp_is_imm( x ) ){
        return wasp_imm_fv( x );
    }else{
        return wasp_integer_fn( (wasp_number)wasp_obj_fv( x ) );
    }
}
wasp_value wasp_vf_integer( wasp_integer x ){
    if(( x < 0 )||( x > WASP_MAX_IMM )){
        return wasp_vf_number( wasp_nf_integer( x ) );
    }else{
        return wasp_vf_imm( x );
    }
}
wasp_boolean wasp_is_integer( wasp_value x ){
    return wasp_is_number( x );
}
wasp_boolean wasp_is_number( wasp_value x ){
    return wasp_is_imm( x ) || ( wasp_obj_type( wasp_obj_fv( x ) ) == wasp_number_type );
}
wasp_integer wasp_req_integer( wasp_value x ){
    if( wasp_is_imm( x ) ){ 
        return wasp_imm_fv( x ); 
    }else if( wasp_is_number( x ) ){
        return wasp_integer_fn( (wasp_number)wasp_obj_fv( x ) );
    }else{
        wasp_errf( wasp_es_vm, "sx", "expected integer", x );
    }
}
wasp_integer wasp_req_intarg( ){
    return wasp_req_integer( wasp_req_any( ) ); 
}
wasp_integer wasp_opt_intarg( wasp_boolean* has ){
    wasp_value x = wasp_opt_any( has );
    if( *has ) return wasp_req_integer( x );
}

WASP_BEGIN_PRIM( "+", plus )
    REQ_INTEGER_ARG( sum );
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        sum += x;
    }
    INTEGER_RESULT( sum );
WASP_END_PRIM( plus )

WASP_BEGIN_PRIM( "-", minus )
    REQ_INTEGER_ARG( base );

    int any = 0;
    
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        any = 1;
        base -= x;
    };

    INTEGER_RESULT( any ? base : - base );
WASP_END_PRIM( minus )

WASP_BEGIN_PRIM( "&", bit_and )
    REQ_INTEGER_ARG( base );
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        base &= x;
    }
    INTEGER_RESULT( base );
WASP_END_PRIM( bit_and )

WASP_BEGIN_PRIM( "|", bit_or )
    REQ_INTEGER_ARG( base );
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        base |= x;
    }
    INTEGER_RESULT( base );
WASP_END_PRIM( bit_or )

WASP_BEGIN_PRIM( "^", bit_xor )
    REQ_INTEGER_ARG( base );
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        base ^= x;
    }
    INTEGER_RESULT( base );
WASP_END_PRIM( bit_xor )

WASP_BEGIN_PRIM( "<<", bit_left )
    REQ_INTEGER_ARG( base );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );
    INTEGER_RESULT( base << offset );
WASP_END_PRIM( bit_left )

WASP_BEGIN_PRIM( ">>", bit_right )
    REQ_INTEGER_ARG( base );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );
    INTEGER_RESULT( base >> offset );
WASP_END_PRIM( bit_right )

WASP_BEGIN_PRIM( "!", bit_not )
    REQ_INTEGER_ARG( base );
    NO_REST_ARGS( );
    INTEGER_RESULT( base ^ 0xFFFFFFFF );
WASP_END_PRIM( bit_not )

void wasp_init_number_subsystem( ){
    WASP_I_TYPE( number );
    WASP_BIND_PRIM( plus );
    WASP_BIND_PRIM( minus );
    WASP_BIND_PRIM( bit_and );
    WASP_BIND_PRIM( bit_or );
    WASP_BIND_PRIM( bit_xor );
    WASP_BIND_PRIM( bit_left );
    WASP_BIND_PRIM( bit_right );
    WASP_BIND_PRIM( bit_not );
    wasp_set_global( 
        wasp_symbol_fs( "*max-int*" ), wasp_vf_integer( WASP_MAX_INT ) );
    wasp_set_global( 
        wasp_symbol_fs( "*max-imm*" ), wasp_vf_integer( WASP_MAX_IMM ) );
    wasp_set_global( 
        wasp_symbol_fs( "*min-int*" ), wasp_vf_integer( WASP_MIN_INT ) );
    wasp_set_global( 
        wasp_symbol_fs( "*min-imm*" ), wasp_vf_integer( WASP_MIN_IMM ) );
}
