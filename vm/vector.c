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

#define WASP_MIN_VECTOR_LEN 64
#define WASP_MIN_VECTOR_SZ ( sizeof( struct wasp_vector_data ) + 64 * sizeof( wasp_value ) ) 

struct wasp_pool_data wasp_vector_scrap_data;
wasp_pool wasp_vector_scrap = &wasp_vector_scrap_data;

wasp_vector wasp_make_vector( wasp_integer length ){
    wasp_vector v;
    size_t tail = sizeof( wasp_value ) * length;
    
    if( length <= WASP_MIN_VECTOR_LEN ){
        v = (wasp_vector) wasp_scavenge( wasp_vector_type, wasp_vector_scrap, WASP_MIN_VECTOR_SZ );
    }else{
        v = WASP_OBJALLOC2( vector, tail );
    }

    v->length = length;
    return v;
}

void wasp_format_vector_items( wasp_string s, wasp_vector v, wasp_boolean sp ){
    wasp_integer ln = wasp_vector_length( v );
    wasp_integer ix = 0;

    for( ix = 0; ix < ln; ix ++ ){
        if( sp ) wasp_string_append_byte( s, ' ' );
        sp = 1;
        if( ! wasp_format_item( s, wasp_vector_get( v, ix ) ) )break;
    }
}
void wasp_format_vector( wasp_string s, wasp_vector v ){
    wasp_format_begin( s, v );
    wasp_format_vector_items( s, v, 1 ); 
    wasp_format_end( s );
}

wasp_vector wasp_copy_vector( wasp_vector vo, wasp_integer ln ){
    wasp_vector vn = wasp_make_vector( ln );
    while( ln-- ){
        wasp_vector_put( vn, ln, wasp_vector_get( vo, ln ) );
    }
    return vn;
}

wasp_integer wasp_vector_compare( wasp_vector a, wasp_vector b ){
    wasp_integer al = wasp_vector_length( a );
    wasp_integer bl = wasp_vector_length( b );
    wasp_integer i, l = ( al > bl )? bl : al;

    for( i = 0; i < l; i ++ ){
        wasp_integer d = wasp_cmp_eq( wasp_vector_get( a, i ),
                                    wasp_vector_get( b, i ) );
        if( d )return d;
    };

    return bl - al;
}
void wasp_trace_vector( wasp_vector v ){
    int i, l = wasp_vector_length( v );

    for( i = 0; i < l; i ++ ){
        wasp_grey_val( wasp_vector_get( v, i ) );
    }
}

void wasp_free_vector( wasp_vector vector ){
    if( vector->length <= WASP_MIN_VECTOR_LEN ){
        wasp_discard( (wasp_object) vector, wasp_vector_scrap );
    }else{
        wasp_objfree( vector );
    }
}
WASP_C_TYPE( vector );

void wasp_init_vector_subsystem( ){
    WASP_I_TYPE( vector );
}

