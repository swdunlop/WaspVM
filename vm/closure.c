/* Copyright (C) 2006, Ephemeral Security, LLC
 * With Modifications Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
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

int wasp_is_function( wasp_value value ){
    return wasp_is_primitive( value ) | wasp_is_closure( value ) | wasp_is_procedure( value );
}

wasp_closure wasp_make_closure( wasp_value name, wasp_instruction inst, wasp_pair env ){
    wasp_closure clos = WASP_OBJALLOC( closure );
    clos->inst = inst;
    clos->env = env;
    clos->name = name;
    return clos;
}

void wasp_trace_closure( wasp_closure clos ){
    wasp_grey_val( wasp_clos_name( clos ) );
    wasp_grey_obj( (wasp_object) wasp_clos_inst( clos )->proc );
    wasp_grey_obj( (wasp_object) wasp_clos_env( clos ) );
}

void wasp_format_closure( wasp_string buf, wasp_closure clos ){
//    wasp_format_begin( buf, clos );
//    wasp_string_append_byte( buf, ' ' );
    wasp_format_item( buf, clos->name );
//    wasp_format_end( buf );
}

wasp_value wasp_function_name( wasp_value function ){
    wasp_value result;

    if( wasp_is_closure( function ) ){
        result = wasp_closure_fv( function )->name;
        if( ! result ) result = function;
    }else if( wasp_is_primitive( function ) ){
        result = wasp_vf_symbol( wasp_primitive_fv( function )->name );
    }else{
        result = function;
    }

    return result;
}
void wasp_format_func( wasp_string buf, wasp_value func ){
    wasp_format_item( buf, wasp_function_name( func ) );
}
WASP_GENERIC_COMPARE( closure );
WASP_GENERIC_FREE( closure );
WASP_C_TYPE( closure );

void wasp_init_closure_subsystem( ){
    WASP_I_TYPE( closure );
}

