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

wasp_multimethod wasp_make_multimethod( 
    wasp_value signature, wasp_value func, wasp_value next
){
    wasp_multimethod m = WASP_OBJALLOC( multimethod );
    m->signature = signature;
    m->func = func;
    m->next = next;
    m->name = wasp_req_symbol( wasp_function_name( func ) );
    return m;
}

void wasp_trace_multimethod( wasp_multimethod m ){
    wasp_grey_val( m->signature );
    wasp_grey_val( m->func );
    wasp_grey_val( m->next );
    wasp_grey_obj( (wasp_object) m->name );
}

wasp_value wasp_reduce_multimethod( wasp_value fn, wasp_list args ){
    wasp_multimethod mm = wasp_multimethod_fv( fn );
    wasp_value arg, sig, sigs = mm->signature;
    for(;;){
        if( wasp_is_true( sigs ) )return mm->func;
        if( wasp_is_null( sigs ) )return args ? mm->next : mm->func;
        if( ! args )return mm->next;
        sig = wasp_car( wasp_pair_fv( sigs ) );
        sigs = wasp_cdr( wasp_pair_fv( sigs ) );
        arg = wasp_car( ( args ) );
        args = wasp_list_fv( wasp_cdr( args ) );
        if( wasp_is_true( sig ) || wasp_isa( arg, sig ) ){
        }else{
            return mm->next;
        }
    }
}

wasp_value wasp_reduce_function( wasp_value fn, wasp_list args ){
    while( wasp_is_multimethod( fn ) ){
        fn = wasp_reduce_multimethod( fn, args );
    }
    return fn;
};

void wasp_format_multimethod( wasp_string buf, wasp_multimethod multimethod ){
//    wasp_format_begin( buf, multimethod );
//    wasp_string_append_byte( buf, ' ' );
    wasp_string_append_sym( buf, multimethod->name );
//    wasp_format_end( buf );
}

WASP_GENERIC_FREE( multimethod );
WASP_GENERIC_COMPARE( multimethod );

WASP_C_TYPE( multimethod );

WASP_BEGIN_PRIM( "make-multimethod", make_multimethod )
    REQ_ANY_ARG( sig );
    REQ_ANY_ARG( pass );
    REQ_ANY_ARG( fail );
    NO_REST_ARGS( );

    if((! wasp_is_true( sig ))&&(! wasp_is_pair( sig ) )){
        wasp_errf( wasp_es_vm, "sx", "expected list or #t", sig );
    };

    if(! wasp_is_function( fail ) ){
        wasp_errf( wasp_es_vm, "sx", "expected function for fail", fail );
    };

    if(! wasp_is_function( pass ) ){
        wasp_errf( wasp_es_vm, "sx", "expected function for pass", pass );
    };
    
    MULTIMETHOD_RESULT( wasp_make_multimethod( sig, pass, fail ) );
WASP_END_PRIM( make_multimethod )

WASP_BEGIN_PRIM( "isa?", isaq )
    REQ_ANY_ARG( value );
    REQ_ANY_ARG( type );
    NO_REST_ARGS( );
    
    if( wasp_is_type( type ) || wasp_is_tag( type ) ){
        BOOLEAN_RESULT( wasp_isa( value, type ) );
    }else{
        FALSE_RESULT( );
    }
WASP_END_PRIM( isaq );

void wasp_init_multimethod_subsystem( ){
    WASP_I_TYPE( multimethod );
    WASP_BIND_PRIM( make_multimethod );
    WASP_BIND_PRIM( isaq );
}
