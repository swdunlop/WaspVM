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

#ifndef WASP_PRIMITIVE_H
#define WASP_PRIMITIVE_H 1

#include "memory.h"

typedef void (*wasp_prim_fn)();

WASP_BEGIN_TYPE( primitive )
    wasp_symbol  name;
    wasp_prim_fn impl;
    wasp_byte    code, a, b; // Only used for instructions.
WASP_END_TYPE( primitive )

#define REQ_PRIMITIVE_ARG( vn ) REQ_TYPED_ARG( vn, primitive )
#define PRIMITIVE_RESULT( vn ) TYPED_RESULT( vn, primitive )
#define OPT_PRIMITIVE_ARG( vn ) OPT_TYPED_ARG( vn, primitive )

static inline wasp_symbol wasp_prim_name( wasp_primitive prim ){ 
    return prim->name;
}
static inline wasp_prim_fn wasp_prim_impl( wasp_primitive prim ){
    return prim->impl;
}

wasp_primitive wasp_make_primitive( const char* name, wasp_prim_fn impl );
void wasp_bind_primitive( const char* name, wasp_prim_fn impl );

extern wasp_pair wasp_arg_ptr;
extern wasp_integer wasp_arg_ct;

#define WASP_BIND_PRIM( pn ) \
    wasp_bind_primitive( wasp_prim_##pn##_name, wasp_prim_##pn );

#define WASP_BEGIN_PRIM( ln, pn ) \
    const char* wasp_prim_##pn##_name = ln; \
    void wasp_prim_##pn( ){

#define WASP_END_PRIM( pn ) };

#define REST_ARGS( vn ) wasp_pair vn = wasp_arg_ptr;
#define NO_REST_ARGS( vn ) wasp_no_more_args( );

void wasp_init_primitive_subsystem( );

#endif
