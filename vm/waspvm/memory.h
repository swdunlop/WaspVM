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
 * aquad with this library; if not, write to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef WASP_MEMORY_H
#define WASP_MEMORY_H 1

#include <stdlib.h>
#include <assert.h>

// Standard integers
#if defined( __OpenBSD__ )

typedef unsigned char wasp_byte;
typedef unsigned short wasp_word;
typedef unsigned long wasp_quad;
typedef signed long wasp_integer;
typedef int wasp_boolean;

#else

#include <stdint.h>

typedef uint8_t wasp_byte;
typedef uint16_t wasp_word;
typedef uint32_t wasp_quad;
typedef int32_t wasp_integer;
typedef int wasp_boolean;

#endif

// Type Macros
#define WASP_H_TP( tn ) \
    extern const char* wasp_##tn##_name; \
    extern wasp_type wasp_##tn##_type;

#define WASP_H_RQ( tn ) \
    wasp_##tn wasp_req_##tn( wasp_value );

#define WASP_H_FV( tn ) \
    static inline wasp_##tn wasp_##tn##_fv( wasp_value val ){ \
        assert( wasp_is_##tn( val ) ); \
        return (wasp_##tn) val; \
    } 

#define WASP_H_VF( tn ) \
    static inline wasp_value wasp_vf_##tn( wasp_##tn val ){ \
        return wasp_vf_obj( (wasp_object) val ); \
    }

#define WASP_H_IS( tn ) \
    static inline int wasp_is_##tn( wasp_value val ){ \
        return wasp_is_subtype( wasp_value_type( val ), wasp_##tn##_type ); \
    }

#define REQ_ANY_ARG( vn ) \
    wasp_value vn = wasp_req_any();

#define REQ_SUBTYPED_ARG( vn, tn ) \
    wasp_##tn vn = wasp_##tn##_fv( wasp_req_st_arg( wasp_##tn##_type ) );

#define REQ_TYPED_ARG( vn, tn ) \
    wasp_##tn vn = wasp_##tn##_fv( wasp_req_arg( wasp_##tn##_type ) );

#define REQ_FUNCTION_ARG( vn ) \
    wasp_value vn = wasp_req_function( wasp_req_any( ) );

#define OPT_ANY_ARG( vn ) \
    wasp_boolean has_##vn; \
    wasp_value vn = wasp_opt_any( &has_##vn );

#define WASP_H_SUBTYPE( st, dt ) \
    typedef wasp_##dt wasp_##st; \
    WASP_H_TYPE( st ) \

#ifdef XXX_NDEBUG

#define OPT_TYPED_ARG( vn, tn ) \
    wasp_boolean has_##vn; \
    wasp_##tn vn = wasp_##tn##_fv( wasp_opt_arg( wasp_##tn##_type, &has_##vn ) );

#define OPT_SUBTYPED_ARG( vn, tn ) \
    wasp_boolean has_##vn; \
    wasp_##tn vn = wasp_##tn##_fv( wasp_opt_st_arg( wasp_##tn##_type, &has_##vn ) );

#else
// The fv assertions may freak out when they see a null..

#define OPT_TYPED_ARG( vn, tn ) \
    wasp_boolean has_##vn; \
    wasp_value vvv_##vn = wasp_opt_arg( wasp_##tn##_type, &has_##vn ); \
    wasp_##tn vn = has_##vn ? wasp_##tn##_fv( vvv_##vn ) : ( (wasp_##tn) 0 );

#define OPT_SUBTYPED_ARG( vn, tn ) \
    wasp_boolean has_##vn; \
    wasp_value vvv_##vn = wasp_opt_st_arg( wasp_##tn##_type, &has_##vn ); \
    wasp_##tn vn = has_##vn ? wasp_##tn##_fv( vvv_##vn ) : ( (wasp_##tn) 0 );

#endif

#define TYPED_RESULT( tn, x ) RESULT( wasp_vf_##tn( x ) );
#define NO_RESULT( ) RESULT( wasp_vf_null() );
#define RESULT( x )  { WASP_RX = (x); return; }

#define WASP_C_TP2( tn, ts ) \
    const char* wasp_##tn##_name = ts; \
    struct wasp_type_data wasp_##tn##_type_data = { { NULL, NULL, NULL, NULL }, NULL, NULL }; \
    wasp_type wasp_##tn##_type = &wasp_##tn##_type_data;

#define WASP_C_TP( tn ) WASP_C_TP2( tn, #tn );

#define WASP_C_RQ( tn ) \
    wasp_##tn wasp_req_##tn( wasp_value val ){ \
        if( wasp_is_##tn( val ) ) \
            return (wasp_##tn) wasp_obj_fv( val ); \
        wasp_errf( wasp_es_vm, "sxx", "type mismatch", wasp_##tn##_type, val ); \
    } 

struct wasp_boolean_data { int x; };
struct wasp_null_data { int x; };
#define WASP_I_TYPE__( tn ) \
    wasp_##tn##_type->format = (wasp_format_mt)wasp_format_##tn; \
    wasp_##tn##_type->trace = (wasp_gc_mt)wasp_trace_##tn; \
    wasp_##tn##_type->free = (wasp_gc_mt)wasp_free_##tn; \
    wasp_##tn##_type->compare = (wasp_cmp_mt)wasp_##tn##_compare; \
    wasp_##tn##_type->header.type = wasp_type_type; \
    wasp_root_obj( (wasp_object)wasp_##tn##_type ); \

#define WASP_I_TYPE_( tn ) \
    WASP_I_TYPE__( tn ) \
    wasp_bind_type( wasp_##tn##_name, wasp_##tn##_type ); \
    
#define WASP_I_TYPE( tn ) \
    wasp_##tn##_type->direct = wasp_##tn##_type; \
    WASP_BIND_PRIM( tn##q ) \
    WASP_I_TYPE_( tn );

#define WASP_C_SUBTYPE( chil, pare ) \
    WASP_C_TYPE( chil ); 

#define WASP_C_SUBTYPE2( chil, chiln, pare ) \
    WASP_C_TYPE2( chil, chiln ); 

#define WASP_I_SUBTYPE( child, pare ) \
    wasp_##child##_type->format = (wasp_format_mt)wasp_format_##child; \
    wasp_##child##_type->trace = (wasp_gc_mt)wasp_trace_##child; \
    wasp_##child##_type->free = (wasp_gc_mt)wasp_free_##child; \
    wasp_##child##_type->compare = (wasp_cmp_mt)wasp_##child##_compare; \
    wasp_##child##_type->direct = wasp_##pare##_type->direct; \
    wasp_##child##_type->parent = wasp_##pare##_type; \
    wasp_##child##_type->header.type = wasp_type_type; \
    wasp_root_obj( (wasp_object)wasp_##child##_type ); \
    wasp_bind_type( wasp_##child##_name, wasp_##child##_type ); \
    WASP_BIND_PRIM( child##q ) \

#define WASP_H_TYPE( tn ) \
    WASP_H_TP( tn ); \
    WASP_H_RQ( tn ); \
    WASP_H_IS( tn ); \
    WASP_H_FV( tn ); \
    WASP_H_VF( tn ); \
    
#define WASP_C_TYPE2( tn, ts ) \
    WASP_C_TP2( tn, ts ); \
    WASP_C_RQ( tn ); \
    WASP_BEGIN_PRIM( ts "?", tn##q ) \
        REQ_ANY_ARG( value ); \
        NO_REST_ARGS( ); \
        \
        BOOLEAN_RESULT( wasp_is_##tn( value ) ); \
    WASP_END_PRIM( tn##q ) \

#define WASP_C_TYPE( tn ) \
    WASP_C_TYPE2( tn, #tn ); 

#define WASP_BEGIN_TYPE( tn ) \
    struct wasp_##tn##_data; \
    typedef struct wasp_##tn##_data* wasp_##tn; \
    struct wasp_##tn##_data{ \
        struct wasp_object_data header; \

#define WASP_END_TYPE( tn ) \
    }; \
    WASP_H_TYPE( tn )

#define WASP_BEGIN_SUBTYPE( pt, tn ) \
    struct wasp_##tn##_data; \
    typedef struct wasp_##tn##_data* wasp_##tn; \
    struct wasp_##tn##_data{ \
        struct wasp_##pt##_data pt; \

#define WASP_END_SUBTYPE( tn ) \
    }; \
    WASP_H_TYPE( tn )

// Fundamental Structures and Constants
typedef wasp_quad wasp_value;

struct wasp_type_data;
typedef struct wasp_type_data* wasp_type;

struct wasp_object_data;
typedef struct wasp_object_data* wasp_object;

struct wasp_pool_data;
typedef struct wasp_pool_data* wasp_pool;

extern wasp_pool wasp_greys, wasp_whites, wasp_blacks, wasp_roots;

#define WASP_MAX_IMM 1073741823
#define WASP_MIN_IMM 0

#define WASP_MAX_INT 2147483646
#define WASP_MIN_INT -2147483646 

struct wasp_object_data {
    wasp_type type;
    wasp_pool pool;
    wasp_object prev, next;
};

struct wasp_pool_data {
    wasp_object head;
    wasp_quad count;
};

void wasp_set_pool( wasp_object obj, wasp_pool pool );
void wasp_trace_obj( wasp_object obj );
void wasp_grey_obj( wasp_object obj );
void wasp_root_obj( wasp_object obj );
void wasp_unroot_obj( wasp_object obj );
void wasp_trace_all( );

WASP_H_TP( null );
static inline wasp_boolean wasp_is_null( wasp_value val ){ return ! val; };
static inline wasp_value wasp_vf_null( ){ return 0; }

extern wasp_type wasp_imm_type;

// Fundamental Conversions & Accessors
static inline int wasp_is_imm( wasp_value val ){ return val & 1; }
static inline int wasp_is_obj( wasp_value val ){ return ! wasp_is_imm( val ); }
static inline wasp_object wasp_obj_fv( wasp_value val ){
    assert( wasp_is_obj( val ) );
    return (wasp_object) val;    
}
static inline wasp_quad wasp_imm_fv( wasp_value val ){
    assert( wasp_is_imm( val ) );
    return (wasp_quad)( val >> 1 );
}
static inline wasp_type wasp_obj_type( wasp_object obj ){
    return obj ? obj->type : wasp_null_type;
}

static inline wasp_type wasp_value_type( wasp_value val ){
    if( wasp_is_obj( val ) ) return wasp_obj_type( wasp_obj_fv( val ) );
    return wasp_imm_type;
}

static inline wasp_value wasp_vf_obj( wasp_object obj ){
    assert( !( ( (wasp_quad) obj) & 1 ) );
    return (wasp_value) obj;
}

static inline wasp_value wasp_vf_imm( wasp_quad imm ){
    assert( imm < ( 1 << 31 ) );
    return( imm << 1) | 1;
}


// Fundamental Memory Operations
#define WASP_OBJALLOC( tn ) WASP_OBJALLOC2( tn, 0 )
#define WASP_OBJALLOC2( tn, sz ) \
    ( (wasp_##tn) wasp_objalloc( wasp_##tn##_type, \
                               sizeof( struct wasp_##tn##_data ) + (sz) ) )

wasp_object wasp_objalloc( wasp_type type, wasp_quad size );
void wasp_objfree( void* obj );

typedef void (*wasp_gc_mt)( wasp_object obj );
typedef wasp_integer (*wasp_cmp_mt)( wasp_value a, wasp_value b );
typedef void (*wasp_format_mt)( void*, wasp_value obj );

#define WASP_INHERIT_MT( child, parent ) \
    WASP_INHERIT_GC( child, parent ); \
    WASP_INHERIT_FORMAT( child, parent ); \
    WASP_INHERIT_COMPARE( child, parent );

#define WASP_GENERIC_MT( type ) \
    WASP_GENERIC_GC( type ); \
    WASP_GENERIC_FORMAT( type ); \
    WASP_GENERIC_COMPARE( type );

#define WASP_INHERIT_GC( child, parent ) \
    WASP_INHERIT_TRACE( child, parent ); \
    WASP_INHERIT_FREE( child, parent );

#define WASP_GENERIC_GC( type ) \
    WASP_GENERIC_TRACE( type ); \
    WASP_GENERIC_FREE( type ); \

#define WASP_GENERIC_TRACE( type ) \
    const wasp_gc_mt wasp_trace_##type = wasp_generic_trace; \

#define WASP_GENERIC_FREE( type ) \
    const wasp_gc_mt wasp_free_##type = wasp_generic_free; 

#define WASP_GENERIC_COMPARE( type ) \
    const wasp_cmp_mt wasp_##type##_compare = wasp_compare_generic;

#define WASP_GENERIC_FORMAT( type ) \
    const wasp_format_mt wasp_format_##type = (wasp_format_mt) wasp_generic_format; 

#define WASP_INHERIT_TRACE( child, parent ) \
    const wasp_gc_mt wasp_trace_##child = (wasp_gc_mt) wasp_trace_##parent; \

#define WASP_INHERIT_FREE( child, parent ) \
    const wasp_gc_mt wasp_free_##child = (wasp_gc_mt) wasp_free_##parent; \

#define WASP_INHERIT_FORMAT( child, parent ) \
    const wasp_format_mt wasp_format_##child = (wasp_format_mt) wasp_format_##parent; \

#define WASP_INHERIT_COMPARE( child, parent ) \
    const wasp_cmp_mt wasp_##child##_compare = (wasp_cmp_mt) wasp_##parent##_compare; \

void wasp_generic_format( void* buf, wasp_value x );
void wasp_generic_trace( wasp_object obj );
void wasp_generic_free( wasp_object obj );
wasp_integer wasp_compare_generic( wasp_value a, wasp_value b );

wasp_integer wasp_cmp_eq( wasp_value a, wasp_value b );
wasp_integer wasp_cmp_eqv( wasp_value a, wasp_value b );

static inline wasp_boolean wasp_eq( wasp_value a, wasp_value b ){
    return ! wasp_cmp_eq( a, b );
}
static inline wasp_boolean wasp_eqv( wasp_value a, wasp_value b ){
    return ! wasp_cmp_eqv( a, b );
}

// The Type Type -- Yes, the redundant redundancy is necessary..
struct wasp_type_data {
    struct wasp_object_data header;
    wasp_type parent;
    wasp_type direct;
    wasp_gc_mt trace;
    wasp_gc_mt free;
    wasp_cmp_mt compare;
    wasp_format_mt format;
    wasp_value name;
};

WASP_H_TYPE( type );
#define REQ_TYPE_ARG( vn ) REQ_TYPED_ARG( vn, type )
#define OPT_TYPE_ARG( vn ) OPT_TYPED_ARG( vn, type )
#define TYPE_RESULT( x ) TYPED_RESULT( type, x )

static inline void wasp_grey_val( wasp_value val ){
    if( wasp_is_obj( val ) )wasp_grey_obj( wasp_obj_fv( val ) );
}

#ifdef WASP_COUNT_GC
extern wasp_quad wasp_object_ct;
#endif 

void wasp_bind_type( const char* name, wasp_type type );

void wasp_collect_garbage( );
void wasp_collect_window( );

wasp_boolean wasp_equal( wasp_value a, wasp_value b );
wasp_boolean wasp_eqv( wasp_value a, wasp_value b );
wasp_boolean wasp_eq( wasp_value a, wasp_value b );

void wasp_init_memory_subsystem( );

wasp_value wasp_req_any( );
wasp_value wasp_req_arg( wasp_type type );
wasp_value wasp_req_st_arg( wasp_type type );
wasp_value wasp_opt_any( wasp_boolean* found );
wasp_value wasp_opt_st_arg( wasp_type type, wasp_boolean* found );
wasp_value wasp_opt_arg( wasp_type type, wasp_boolean* found );

void wasp_no_more_args( );

wasp_type wasp_make_type( wasp_value name, wasp_type parent );
wasp_type wasp_direct_type( wasp_value value );

void wasp_unpool_obj( wasp_object obj );
void wasp_pool_obj( wasp_object obj, wasp_pool pool );
wasp_object wasp_scavenge( wasp_type type, wasp_pool pool, wasp_quad size );
void wasp_discard( wasp_object obj, wasp_pool pool );

#endif
