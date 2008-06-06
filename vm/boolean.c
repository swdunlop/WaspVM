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

wasp_value wasp_the_true;
wasp_value wasp_the_false;

void wasp_format_boolean( wasp_string buf, wasp_value v ){
    wasp_string_append_cs( buf, v == wasp_the_false ? "#f" : "#t" );
}
wasp_integer wasp_boolean_compare( wasp_value a, wasp_value b ){
    if( a == b )return 0;
    return ( a == wasp_the_false ) ? -1 : +1;
}
WASP_GENERIC_GC( boolean );
WASP_C_TYPE( boolean );

wasp_value wasp_make_mote( wasp_type type ){
    wasp_object mote = wasp_objalloc( type, sizeof( struct wasp_object_data ) );
    wasp_root_obj( mote );
    return wasp_vf_obj( mote );
}

void wasp_init_boolean_subsystem( ){
    WASP_I_TYPE( boolean );
    wasp_the_true = wasp_make_mote( wasp_boolean_type );
    wasp_the_false = wasp_make_mote( wasp_boolean_type );
}
