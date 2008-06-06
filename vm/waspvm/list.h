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

#ifndef WASP_LIST_H
#define WASP_LIST_H 1

#include "memory.h"

WASP_BEGIN_TYPE( pair )
    wasp_value car, cdr;
WASP_END_TYPE( pair )

#define REQ_PAIR_ARG( vn ) REQ_TYPED_ARG( vn, pair )
#define PAIR_RESULT( vn ) TYPED_RESULT( vn, pair )
#define OPT_PAIR_ARG( vn ) OPT_TYPED_ARG( vn, pair )

WASP_H_SUBTYPE( tc, pair );

#define REQ_TC_ARG( vn ) REQ_TYPED_ARG( vn, tc )
#define TC_RESULT( vn ) TYPED_RESULT( vn, tc )
#define OPT_TC_ARG( vn ) OPT_TYPED_ARG( vn, tc )

#define wasp_list wasp_pair
#define wasp_list_type wasp_pair_type

static inline wasp_boolean wasp_is_list( wasp_value v ){
    return wasp_is_pair( v ) || wasp_is_null( v );
}

static inline wasp_list wasp_list_fv( wasp_value v ){
    assert( wasp_is_list( v ) );
    return (wasp_list)v;
}

static inline wasp_list wasp_req_list( wasp_value v ){
    return( wasp_is_null( v ) ) ? NULL : wasp_req_pair( v );
}

#define wasp_vf_list wasp_vf_pair
#define REQ_LIST_ARG( vn ) wasp_list vn = wasp_req_list( wasp_req_any( ) );
#define LIST_RESULT( vn ) TYPED_RESULT( list, vn )
#define OPT_LIST_ARG( vn ) wasp_boolean has_##vn = 1; wasp_list vn = wasp_opt_list( &has_##vn );

static inline wasp_value wasp_car( wasp_pair pair ){ 
    assert( pair );
    return pair->car; 
}
static inline wasp_value wasp_cdr( wasp_pair pair ){ 
    assert( pair );
    return pair->cdr;
}
static inline wasp_value wasp_set_car( wasp_pair pair, wasp_value x ){ 
    assert( pair );
    pair->car = x; 
}
static inline wasp_value wasp_set_cdr( wasp_pair pair, wasp_value x ){ 
    assert( pair );
    pair->cdr = x; 
}
void wasp_format_list_items( void* b, wasp_pair p, wasp_boolean sp );
static inline wasp_list wasp_opt_list( wasp_boolean* has ){
    wasp_value v = wasp_opt_any( has );
    return ( *has ) ? wasp_req_list( v ) : NULL;
}
wasp_pair wasp_cons( wasp_value car, wasp_value cdr );
wasp_list wasp_list_ref( wasp_list p, wasp_integer ofs );

wasp_tc wasp_make_tc( );
void wasp_tc_append( wasp_tc tc, wasp_value v );

wasp_boolean wasp_eqvp( wasp_pair a, wasp_pair b );
wasp_boolean wasp_equalp( wasp_pair a, wasp_pair b );
wasp_pair wasp_last_pair( wasp_list p );

void wasp_format_pair( void * b, wasp_pair p );
void wasp_init_list_subsystem( );
wasp_integer wasp_list_length( wasp_list p );

wasp_pair wasp_listf( wasp_integer ct, ... );
#endif
