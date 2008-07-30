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

#ifndef WASP_MULTIMETHOD_H
#define WASP_MULTIMETHOD_H 1

#include "memory.h"

WASP_BEGIN_TYPE( multimethod )
    wasp_value     signature;
    wasp_value     func;
    wasp_value     next;
    wasp_symbol    name;
WASP_END_TYPE( multimethod )

#define REQ_MULTIMETHOD_ARG( vn ) REQ_TYPED_ARG( vn, multimethod )
#define MULTIMETHOD_RESULT( vn ) TYPED_RESULT( multimethod, vn )
#define OPT_MULTIMETHOD_ARG( vn ) OPT_TYPED_ARG( vn, multimethod )

wasp_multimethod wasp_make_multimethod( 
    wasp_value signature, wasp_value func, wasp_value next
);
wasp_value wasp_reduce_function( wasp_value func, wasp_list args );

void wasp_init_multimethod_subsystem( );

static inline wasp_boolean wasp_is_function( wasp_value v ){
    return wasp_is_closure( v ) 
        || wasp_is_primitive( v ) 
        || wasp_is_procedure( v )
        || wasp_is_multimethod( v );
}

#endif
