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
#include <string.h>

#ifdef WASP_IN_WIN32
#include <malloc.h>
#endif

void wasp_unpool_obj( wasp_object obj ){
    if( obj->pool ){
        if( obj->prev ){
            obj->prev->next = obj->next;
        }else{
            obj->pool->head = obj->next;
        };

        if( obj->next ){
            obj->next->prev = obj->prev;
        };
    }
}

void wasp_pool_obj( wasp_object obj, wasp_pool pool ){
    obj->pool = pool;
    obj->prev = NULL;
    obj->next = pool->head;
    if( obj->next ) obj->next->prev = obj;
    pool->head = obj;
}

#ifdef WASP_COUNT_GC
wasp_quad wasp_object_ct = 0;
#endif

#define WASP_MIN_TOLERANCE 1024
#define WASP_MAX_TOLERANCE 16384
#define WASP_MAX_SCRAP     16384

wasp_quad wasp_new_tolerance = WASP_MIN_TOLERANCE;
wasp_quad wasp_new_objects = 0;

void wasp_discard( wasp_object obj, wasp_pool pool ){
    wasp_unpool_obj( obj );

    if( pool->count < WASP_MAX_SCRAP ){
        wasp_pool_obj( obj, pool );
        pool->count ++;
    }else{
        free( obj );
    }
}
wasp_object wasp_scavenge( wasp_type type, wasp_pool pool, wasp_quad size ){
    wasp_object obj;

    if( pool->head ){
        obj = pool->head;
        wasp_unpool_obj( obj );
#ifdef WASP_IN_WIN32
        memset( obj, 0, size );
#else
        bzero( obj, size );
#endif
        obj->type = type;
        wasp_pool_obj( obj, wasp_blacks );
        //wasp_printf( "sxn", "Hit for ", type );
        pool->count --;
        return obj;
    }else{
        //wasp_printf( "sxn", "Miss for ", type );
        return wasp_objalloc( type, size );
    }
}
wasp_object wasp_objalloc( wasp_type type, wasp_quad size ){
    #ifdef WASP_COUNT_GC
    wasp_object_ct ++;
    #endif
    
    wasp_new_objects++;

    assert( size >= sizeof( struct wasp_object_data ) );

    wasp_object obj = (wasp_object) malloc( size );
    //TODO: Remove all inits of = NULL;
#ifdef WASP_IN_WIN32
        memset( obj, 0, size );
#else
        bzero( obj, size );
#endif

    //TODO: WASP_RESTORE: if(! obj )wasp_errf( wasp_es_mem, "sxi", "out of memory", type, size );
    assert( obj );
    obj->type = type;

    wasp_pool_obj( obj, wasp_blacks );
    assert( ! ( ((wasp_quad)obj) & 1 ) );
    return obj;
}
void wasp_objfree( void* obj ){
    #ifdef WASP_COUNT_GC
    wasp_object_ct --;
    #endif
    
    wasp_unpool_obj( (wasp_object) obj );
    free( obj );
}

void wasp_root_value( wasp_value val ){
    if( wasp_is_obj( val ) ) wasp_root_obj( wasp_obj_fv( val ) );
}

void wasp_root_obj( wasp_object obj ){
    if( obj == NULL )return;
    assert( obj->type );
    //TODO: Assertions against rooting during garbage collection.
    wasp_unpool_obj( obj );
    wasp_pool_obj( obj, wasp_roots );
}

void wasp_unroot_obj( wasp_object obj ){
    if( obj == NULL )return;
    assert( obj->type );
    //TODO: Assertions against rooting during garbage collection.
    wasp_unpool_obj( obj );
    wasp_pool_obj( obj, wasp_blacks );
}

void wasp_grey_obj( wasp_object obj ){
    if( obj == NULL )return;

    wasp_pool pool = obj->pool;
    if( pool == wasp_greys )return;
    if( pool == wasp_whites )return;
    if( pool == wasp_roots )return;
    
    wasp_new_tolerance++;

    wasp_unpool_obj( obj );
    wasp_pool_obj( obj, wasp_greys );
}

void wasp_trace_object( wasp_object obj ){
    wasp_grey_obj( (wasp_object)obj->type );
    obj->type->trace( obj );
}
//wasp_integer wasp_since = 0;
void wasp_collect_window( ){
    //wasp_since ++;
    if( wasp_new_objects > wasp_new_tolerance )wasp_collect_garbage( );
}
void wasp_collect_garbage( ){
    // return; // DEBUG: HERE WE GO AGAIN
    //printf( "Beginning GC at %i; old %i v. new %i..\n", wasp_since, wasp_old_objects, wasp_new_objects );
    wasp_object obj;

    wasp_new_tolerance = wasp_new_objects = 0;

    for( obj = wasp_roots->head; obj; obj = obj->next ){
        wasp_new_tolerance++;
        wasp_trace_object( obj );
    }
    
    wasp_trace_registers();
    wasp_trace_actives();
    // TODO: Not used, atm. wasp_trace_network();

    while( obj = wasp_greys->head ){
        wasp_new_tolerance++;
        wasp_unpool_obj( obj );
        wasp_pool_obj( obj, wasp_whites );
        wasp_trace_object( obj );
    }
    
    while( obj = wasp_blacks->head ){
        obj->type->free( obj );    
    }
    
    wasp_pool temp = wasp_whites;
    wasp_whites = wasp_blacks;
    wasp_blacks = temp;

    //printf( ".. GC Complete, kept %i..\n", wasp_old_objects );

    if( wasp_new_tolerance < WASP_MIN_TOLERANCE ){
        wasp_new_tolerance = WASP_MIN_TOLERANCE;
    }else if( wasp_new_tolerance > WASP_MAX_TOLERANCE ){
        wasp_new_tolerance = WASP_MAX_TOLERANCE;
    }
}

void wasp_generic_trace( wasp_object obj ){}
void wasp_generic_free( wasp_object obj ){ wasp_objfree( obj ); }

struct wasp_pool_data wasp_blacks_data = { NULL };
wasp_pool wasp_blacks = &( wasp_blacks_data );

struct wasp_pool_data wasp_greys_data = { NULL };
wasp_pool wasp_greys = &( wasp_greys_data );

struct wasp_pool_data wasp_whites_data = { NULL };
wasp_pool wasp_whites = &( wasp_whites_data );

struct wasp_pool_data wasp_roots_data = { NULL };
wasp_pool wasp_roots = &( wasp_roots_data );

wasp_type wasp_make_type( wasp_value name, wasp_type parent ){
    wasp_type direct, type = WASP_OBJALLOC( type );

    if(! parent ){
    }else if(! parent->direct ){
        type->direct = parent;
        direct = parent;
    }else{
        type->direct = parent->direct;
    }

    type->name = name;
    type->parent = parent;

    return type;
}

void wasp_trace_type( wasp_type type ){
    wasp_grey_obj( (wasp_object) type->parent );
    wasp_grey_obj( (wasp_object) type->direct );
    wasp_grey_obj( (wasp_object) type->name );
}

void wasp_format_type( wasp_string buf, wasp_type type ){
    wasp_string_append_byte( buf, '<' );
    //TODO: Clean up -- type->name type should be symbol..
    wasp_string_append_sym( buf, wasp_symbol_fv( type->name ) );
    wasp_string_append_byte( buf, '>' );
}

void wasp_generic_format( void* bbuf, wasp_value value ){
    wasp_string buf = bbuf; 
    wasp_format_begin( buf, wasp_obj_fv( value ) );
    wasp_string_append_byte( buf, ' ' );
    wasp_string_append_addr( buf, value );
    wasp_format_end( buf );
}

WASP_GENERIC_COMPARE( type );
WASP_GENERIC_FREE( type );
WASP_C_TYPE( type );

void wasp_format_null( wasp_string buf, wasp_value null ){
    wasp_string_append_cs( buf, "null" );
}

WASP_GENERIC_COMPARE( null );
WASP_GENERIC_GC( null );
WASP_C_TP( null );

WASP_GENERIC_COMPARE( imm );
WASP_GENERIC_GC( imm );

void wasp_format_imm( wasp_string s, wasp_quad imm ){ 
    wasp_string_append_unsigned( s, imm >> 1 ); 
};

struct wasp_type_data wasp_imm_type_data = { 
    {NULL, NULL, NULL, NULL }, NULL, NULL 
};
wasp_type wasp_imm_type = &wasp_imm_type_data;

void wasp_bind_type( const char* name, wasp_type type ){
    int namelen = strlen( name );
    char* buf = alloca( namelen + 2 );
    memcpy( buf + 1, name, namelen );
    buf[0] = '<';
    buf[namelen + 1] = '>';
    wasp_symbol sym = wasp_symbol_fm( buf, namelen + 2 );
    wasp_set_global( sym, wasp_vf_type( type ) );
    type->name = wasp_vf_symbol( wasp_symbol_fs( name ) );
}

wasp_integer wasp_cmp_eqv( wasp_value a, wasp_value b ){
    wasp_type at, bt;

    if( wasp_is_number( a ) ){
        at = wasp_number_type;
    }else{
        at = wasp_value_type( a );
    };

    if( wasp_is_number( b ) ){
        bt = wasp_number_type;
    }else{
        bt = wasp_value_type( b );
    };
   
    if( at == bt )return at->compare( a, b ); 
    if( at < bt )return -1;
    if( at > bt )return +1;
    return 0;
}

wasp_integer wasp_cmp_eq( wasp_value a, wasp_value b ){
    if( a == b ) return 0;

    if( wasp_is_number( a ) && wasp_is_number( b ) ){
        return wasp_number_compare( a, b );
    }else if( wasp_is_string( a ) && wasp_is_string( b ) ){
        return wasp_string_compare( wasp_string_fv( a ), wasp_string_fv( b ) );
    };

    if( a < b )return -1;
    if( a > b )return +1;
}

wasp_integer wasp_compare_generic( wasp_value a, wasp_value b ){
    return a - b;
}

WASP_BEGIN_PRIM( "null?", nullq )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    BOOLEAN_RESULT( wasp_is_null( value ) );
WASP_END_PRIM( nullq )

void wasp_init_memory_subsystem( ){
    wasp_imm_type = wasp_number_type;
    wasp_string_type->format = (wasp_format_mt)wasp_format_string;
    wasp_string_type->compare = (wasp_cmp_mt)wasp_string_compare;
    WASP_I_TYPE( type );
    WASP_I_TYPE( null );
    //TODO: bind *null* to wasp_vf_null
}
wasp_value wasp_req_any( ){
    if( wasp_arg_ptr ){
        wasp_value x = wasp_car( wasp_arg_ptr );
        wasp_arg_ptr = wasp_list_fv( wasp_cdr( wasp_arg_ptr ) );
        return x;
    }else{
        wasp_errf( wasp_es_vm, "s", "argument underflow" );
    }
}
wasp_value wasp_req_arg( wasp_type type ){
    wasp_value x = wasp_req_any( );
    if( wasp_value_type( x ) == type ){
        return x;
    }
    wasp_errf( wasp_es_vm, "sxx", "argument type mismatch", type, x );
}
wasp_value wasp_req_st_arg( wasp_type type ){
    wasp_value x = wasp_req_any( );
    if( wasp_is_subtype( wasp_value_type( x ),  type ) ){
        return x;
    }
    wasp_errf( wasp_es_vm, "sxx", "argument type mismatch", type, x );
}
wasp_value wasp_opt_any( wasp_boolean* found ){
    if( wasp_arg_ptr ){
        wasp_value x = wasp_car( wasp_arg_ptr );
        wasp_arg_ptr = wasp_list_fv( wasp_cdr( wasp_arg_ptr ) );
        *found = 1;
        return x;
    }else{
        *found = 0;
        return 0;
    }
}
wasp_value wasp_opt_arg( wasp_type type, wasp_boolean* found ){
    wasp_value x = wasp_opt_any( found );
    if( *found ){
        if( wasp_value_type( x ) == type ){
            return x;
        }
        wasp_errf( wasp_es_vm, "sxx", "argument type mismatch", type, x );
    }else{ 
        return 0;
    }
}
wasp_value wasp_opt_st_arg( wasp_type type, wasp_boolean* found ){
    wasp_value x = wasp_opt_any( found );
    if( *found ){
        if( wasp_is_subtype( wasp_value_type( x ),  type ) ){
            return x;
        }
        wasp_errf( wasp_es_vm, "sxx", "argument type mismatch", type, x );
    }else{ 
        return 0;
    }
}
wasp_type wasp_direct_type( wasp_value value ){
    wasp_type type = wasp_value_type( value );
    return type->direct ? type->direct : type;
}
wasp_boolean wasp_is_subtype( wasp_type t1, wasp_type t2 ){
    for(;;){
        if( t1 == t2 )return 1;
        t1 = t1->parent;
        if( ! t1 )return 0;
    }
}

wasp_boolean wasp_isa( wasp_value x, wasp_value t ){
    if( wasp_is_type( t ) ){
        return wasp_is_subtype( wasp_value_type( x ), wasp_type_fv( t ) );
    }else if( wasp_is_cell( x ) && wasp_is_tag( t ) ){
        return wasp_cell_fv( x )->tag == wasp_tag_fv( t );
    }else{
        return 0;
    }
}

