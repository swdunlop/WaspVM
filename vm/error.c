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
#include <stdarg.h>

int wasp_abort_on_error = 0;

void wasp_format_error( wasp_string buf, wasp_error e ){
    wasp_format_begin( buf, e );
    wasp_string_append_byte( buf, ' ' );
    wasp_string_append_sym( buf, e->key );
    wasp_format_list_items( buf, e->info, 1 );
    wasp_format_end( buf );
}

int wasp_format_context( wasp_string buf, wasp_list context  ){
    if( context == NULL )return 0; 
    
    if( wasp_format_context( buf, wasp_list_fv( wasp_cdr( context ) ) ) ){ 
        wasp_string_append_indent( buf, 11 ); 
    }else{ 
        wasp_string_append_cs( buf, "TRACEBACK: " ); 
    };
    
    wasp_format_value( buf, wasp_car( context ), 32, 3 );
    wasp_string_append_newline( buf );

    return 1;
}

void wasp_format_why( wasp_string buf, wasp_error e ){
    wasp_string_append_sym( buf, e->key );

    wasp_pair p = e->info;

    if( p ){
        wasp_value v = wasp_car( e->info );
        if( wasp_is_string( v ) ){
            wasp_string_append_cs( buf, "--" );
            wasp_string_append_str( buf, wasp_string_fv( v ) );
            wasp_string_append_newline( buf );
            wasp_string_append_cs( buf, "      " );
            
            if( wasp_is_list( wasp_cdr( p ) ) ){
                p = wasp_list_fv( wasp_cdr( p ) );
            }else{
                p = NULL;
            }
        }else{
            wasp_string_append_cs( buf, " ::" );
        };
    
        wasp_value x = wasp_vf_list( p );
        while( x ){
            if( wasp_is_pair( x ) ){
                p = wasp_pair_fv( x );
                wasp_string_append_byte( buf, ' ' );
                wasp_format_value( buf, wasp_car( p ), 32, 3 );
                x = wasp_cdr( p );
            }else{
                wasp_string_append_cs( buf, " . " );
                wasp_format_value( buf, x, 32, 3 );
                x = 0;
            };
        };
    };
}
void wasp_format_traceback( wasp_string buf, wasp_error e ){
    wasp_string_append_cs( buf, "ERROR: " );
    wasp_format_why( buf, e );
    wasp_string_append_newline( buf );
    wasp_format_context( buf, e->context );
}

wasp_error wasp_make_error( wasp_symbol key, wasp_list info, wasp_list context ){
    wasp_error e = WASP_OBJALLOC( error );
    e->key = key;
    e->info = info;
    e->context = context;
    return e;
}

wasp_list wasp_frame_context( wasp_callframe cp ){
    wasp_tc t1 = wasp_make_tc( );

    while( cp ){
        wasp_tc_add( t1, wasp_vf_pair( cp->head ) );
        cp = cp->cp;
    }

    return t1->head;
}

void wasp_trace_error( wasp_error e ){
    wasp_grey_obj( (wasp_object) e->key );
    wasp_grey_obj( (wasp_object) e->info );
    wasp_grey_obj( (wasp_object) e->context );
}

void wasp_throw_error( wasp_error e ){
    if( WASP_GP ){
        wasp_guard g = wasp_guard_fv( wasp_car( WASP_GP ) );
        WASP_GP = wasp_list_fv( wasp_cdr( WASP_GP ) );
        WASP_CP = g->cp;
        WASP_EP = g->ep;
        WASP_IP = g->ip;
        WASP_T = g->t;

        WASP_AP = wasp_make_callframe( );
        WASP_AP->ap = g->ap;
        WASP_AP->cp = WASP_CP;
        WASP_AP->ep = WASP_EP;
        WASP_AP->ip = WASP_IP;
        WASP_CP = WASP_AP;

        wasp_chainf( g->fn, 1, e );
    }else{
        wasp_string s = wasp_make_string( 128 );
        wasp_format_traceback( s, e ); 
        wasp_printstr( s );
        if( wasp_abort_on_error ){
            abort( );
        }else{
            exit( 1 );
        }
    }
}

void wasp_errf( wasp_symbol key, const char* fmt, ... ){
    va_list ap;
    wasp_pair head = NULL;
    wasp_pair tail = NULL;
    wasp_pair item = NULL;
   
    const char* ptr = fmt;
    va_start( ap, fmt );
    for(;;){
        wasp_value value;

        switch( *(ptr++) ){
        case 'x':
            value = va_arg( ap, wasp_value );
            break;
        case 's':
            value = wasp_vf_string( wasp_string_fs( va_arg( ap, const char* ) ) );
            break;
        case 'i':
            value = wasp_vf_integer( va_arg( ap, wasp_integer ) );
            break;
        case 0:
            goto done;
        default:
            va_end( ap );
            wasp_errf( wasp_es_vm, "ss",
                "wasp_errf cannot process format string", fmt );
        };

        item = wasp_cons( value, wasp_vf_null( ) );
        if( tail ){
            wasp_set_cdr( tail, wasp_vf_pair( item ) );
        }else{
            head = item;
        };
        tail = item;
    }
done:
    va_end( ap );
    wasp_throw_error( wasp_make_error( key, head, wasp_frame_context( WASP_CP ) ) );
}

WASP_GENERIC_COMPARE( error );
WASP_GENERIC_FREE( error );
WASP_C_TYPE( error );

wasp_guard wasp_make_guard( 
    wasp_value fn, wasp_callframe cp, wasp_callframe ap, wasp_pair ep, 
    wasp_instruction ip, wasp_integer t
){
    wasp_guard g = WASP_OBJALLOC( guard );

    g->fn = fn;
    g->ap = ap;
    g->cp = cp;
    g->ip = ip;
    g->ep = ep;
    g->t = t;

    return g;
}
void wasp_format_guard( wasp_string buf, wasp_guard guard ){
    wasp_format_begin( buf, guard );
    wasp_string_append_byte( buf, ' ' );
    wasp_format_item( buf, guard->fn );
    wasp_format_end( buf );
}
void wasp_trace_guard( wasp_guard guard ){
    wasp_grey_val( guard->fn );
    wasp_grey_obj( (wasp_object) guard->cp );
    wasp_grey_obj( (wasp_object) guard->ap );
    wasp_grey_obj( (wasp_object) guard->ep );
    if( guard->ip )wasp_grey_obj( (wasp_object) guard->ip->proc );
}
WASP_GENERIC_FREE( guard );
WASP_GENERIC_COMPARE( guard );
WASP_C_TYPE( guard );

WASP_BEGIN_PRIM( "error", error )
    REQ_SYMBOL_ARG( key );
    REST_ARGS( info );
    
    wasp_error err = wasp_make_error( key, info, 
                                    wasp_frame_context( WASP_CP ) );

    wasp_throw_error( err );
WASP_END_PRIM( error )

WASP_BEGIN_PRIM( "traceback", traceback )
    REQ_ERROR_ARG( error );
    OPT_ANY_ARG( dest );
    NO_REST_ARGS( );
    
    if( ! has_dest ){
        wasp_string s = wasp_make_string( 128 );
        wasp_format_traceback( s, error );
        wasp_printstr( s );
        wasp_objfree( s );
    }else if( wasp_is_output( dest ) ){
        wasp_string s = wasp_make_string( 128 );
        wasp_format_traceback( s, error );
        wasp_output_fv( dest )->xmit( wasp_output_fv( dest ), wasp_vf_string( s ) );
    }else{
        wasp_string s = wasp_req_string( dest );
        wasp_format_traceback( s, error );
    }

    NO_RESULT( );
WASP_END_PRIM( traceback )

WASP_BEGIN_PRIM( "re-error", re_error )
    REQ_ERROR_ARG( error );
    NO_REST_ARGS( );
    
    wasp_throw_error( error );

    NO_RESULT( );
WASP_END_PRIM( re_error )

void wasp_init_error_subsystem( ){
    WASP_I_TYPE( error );
    WASP_I_TYPE( guard );
    WASP_BIND_PRIM( error );
    WASP_BIND_PRIM( traceback );
    WASP_BIND_PRIM( re_error );
}

