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

wasp_primitive wasp_make_primitive( const char* name, wasp_prim_fn impl ){
    wasp_primitive prim = WASP_OBJALLOC( primitive );
    prim->name = wasp_symbol_fs( name );
    prim->impl = impl;
    return prim;
}
void wasp_bind_primitive( const char* name, wasp_prim_fn impl ){
    wasp_primitive prim = wasp_make_primitive( name, impl );
    wasp_set_global( prim->name, wasp_vf_primitive( prim ) );
}
void wasp_trace_primitive( wasp_primitive prim ){
    wasp_grey_obj( (wasp_object) wasp_prim_name( prim ) );
}
void wasp_format_primitive( wasp_string buf, wasp_primitive prim ){
//    wasp_format_begin( buf, prim );
//    wasp_string_append_byte( buf, ' ' );
    wasp_string_append_sym( buf, wasp_prim_name( prim ) );
//    wasp_format_end( buf );
}

wasp_pair wasp_arg_ptr = NULL;
wasp_integer wasp_arg_ct = 0;

void wasp_no_more_args( ){
    if( wasp_arg_ptr != NULL ){
        wasp_errf( wasp_es_vm, "s", "expected no more arguments" );
    }
}

WASP_GENERIC_COMPARE( primitive );
WASP_GENERIC_FREE( primitive );
WASP_C_TYPE( primitive );

void wasp_init_primitive_subsystem( ){
    WASP_I_TYPE( primitive );
}

