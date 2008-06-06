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
 * along with this library; if not, print to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "waspvm.h"

wasp_tag wasp_make_tag( wasp_symbol name, wasp_value info ){
    wasp_tag tag = WASP_OBJALLOC( tag );
    tag->name = name;
    tag->info = info;
    return tag;
}
void wasp_trace_tag( wasp_tag t ){
    wasp_grey_obj( (wasp_object)t->name );
    wasp_grey_val( t->info );
}
void wasp_format_tag( wasp_string buf, wasp_tag t ){
    wasp_string_append_byte( buf, '<' );
    wasp_string_append_sym( buf, t->name );
    if( wasp_is_pair( t->info ) ){
        wasp_format_list_items( buf, wasp_pair_fv( t->info ), 1 );
    }else if( t->info ){
        wasp_string_append_cs( buf, " . " );
        wasp_format_item( buf, t->info );
    };
    wasp_string_append_byte( buf, '>' );
}
WASP_GENERIC_COMPARE( tag );
WASP_GENERIC_FREE( tag );
WASP_C_TYPE( tag );

wasp_cell wasp_make_cell( wasp_tag tag, wasp_value repr ){
    wasp_cell cell = WASP_OBJALLOC( cell );
    cell->tag = tag;
    cell->repr = repr;
    return cell;
}
void wasp_format_cell( wasp_string buf, wasp_cell c ){
    wasp_string_append_byte( buf, '[' );
    wasp_string_append_sym( buf, c->tag->name );
    wasp_string_append_byte( buf, ' ' );
    wasp_format_item( buf, c->repr );
    wasp_string_append_byte( buf, ']' );
}
void wasp_trace_cell( wasp_cell c ){
    wasp_grey_obj( (wasp_object) c->tag );
    wasp_grey_val( c->repr );
}
/* wasp_integer wasp_cell_compare( wasp_cell a, wasp_cell b ){
    wasp_integer d = a->tag - b->tag;
    if( d )return d;
    return wasp_cmp_eqv( a->repr, b->repr ); 
} */
WASP_GENERIC_COMPARE( cell );
WASP_GENERIC_FREE( cell );
WASP_C_TYPE( cell );

WASP_BEGIN_PRIM( "type-name", type_name )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    RESULT( wasp_is_tag( value ) ? wasp_vf_symbol( wasp_tag_fv( value )->name )
                                : wasp_req_type( value )->name );
WASP_END_PRIM( type_name )

WASP_BEGIN_PRIM( "type", xtype )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );

    if( wasp_is_cell( value ) ){
        TAG_RESULT( wasp_cell_fv( value )->tag );
    }else{
        TYPE_RESULT( wasp_value_type( value ) );
    }
WASP_END_PRIM( xtype );


WASP_BEGIN_PRIM( "repr", repr )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );

    if( wasp_is_cell( value ) ){
        RESULT( wasp_cell_fv( value )->repr );
    }else{
        RESULT( value );
    }
WASP_END_PRIM( repr );

WASP_BEGIN_PRIM( "tag", tag )
    REQ_CELL_ARG( cell );
    NO_REST_ARGS( );

    TAG_RESULT( cell->tag );
WASP_END_PRIM( tag );

WASP_BEGIN_PRIM( "make-tag", make_tag )
    REQ_SYMBOL_ARG( name );
    REST_ARGS( info );
    TAG_RESULT( wasp_make_tag( name, wasp_vf_pair( info ) ) );
WASP_END_PRIM( make_tag );

WASP_BEGIN_PRIM( "tag-info", tag_info )
    REQ_TAG_ARG( tag );
    NO_REST_ARGS( );
    RESULT( tag->info );
WASP_END_PRIM( tag_info );

WASP_BEGIN_PRIM( "cell", cell )
    REQ_TAG_ARG( tag );
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    RESULT( wasp_vf_cell( wasp_make_cell( tag, value ) ) );
WASP_END_PRIM( cell );

void wasp_init_tag_subsystem( ){
    WASP_I_TYPE( cell );
    WASP_I_TYPE( tag );
    WASP_BIND_PRIM( type_name );
    WASP_BIND_PRIM( xtype );
    WASP_BIND_PRIM( make_tag );
    WASP_BIND_PRIM( tag_info );
    WASP_BIND_PRIM( cell );
    WASP_BIND_PRIM( tag );
    WASP_BIND_PRIM( repr );
}

