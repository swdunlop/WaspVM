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

#ifndef WASP_VECTOR_H
#define WASP_VECTOR_H 1

#include "memory.h"

WASP_BEGIN_TYPE( vector )
    wasp_integer  length;
    wasp_value data[0];
WASP_END_TYPE( vector )
#define REQ_VECTOR_ARG( vn ) REQ_TYPED_ARG( vn, vector )
#define VECTOR_RESULT( vn ) TYPED_RESULT( vn, vector )
#define OPT_VECTOR_ARG( vn ) OPT_TYPED_ARG( vn, vector )

wasp_vector wasp_make_vector( wasp_integer length );
static inline wasp_integer wasp_vector_length( wasp_vector v ){ 
    return v->length; 
}
static inline wasp_value *wasp_vector_ref( wasp_vector v, wasp_integer offset ){
    assert( 0 <= offset );
    assert( offset < v->length ); 
    return v->data + offset;
}
static inline wasp_value wasp_vector_get( wasp_vector v, wasp_integer offset ){ 
    return *(wasp_vector_ref( v, offset )); 
}
static inline void wasp_vector_put( wasp_vector v, wasp_integer offset, 
                                   wasp_value x ){
    *(wasp_vector_ref( v, offset )) = x; 
}

wasp_vector wasp_copy_vector( wasp_vector vo, wasp_integer ln );

wasp_boolean wasp_eqvv( wasp_vector v1, wasp_vector v2 );
wasp_boolean wasp_equalv( wasp_vector v1, wasp_vector v2 );

void wasp_show_vector_contents( wasp_vector p, wasp_word* ct );
void wasp_show_vector( wasp_vector p, wasp_word* ct );

void wasp_init_vector_subsystem( );

#endif
