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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void wasp_format_begin( wasp_string buf, void* oo ){
    wasp_object o = (wasp_object)oo; 
    wasp_string_append_byte( buf, '[' );
    //TODO: Gross assumption -- need to correct type->name type to symbol only
    wasp_string_append_sym( buf, wasp_symbol_fv( o->type->name ) );
}
void wasp_format_end( wasp_string buf ){
    wasp_string_append_byte( buf, ']' );
}

wasp_quad wasp_format_depth;
wasp_quad wasp_format_breadth;
wasp_quad wasp_format_re_breadth;

int wasp_format_item( wasp_string s, wasp_value v ){
    switch( wasp_format_breadth ){
    case 1:
        wasp_format_breadth --;
        wasp_string_append_cs( s, "..." );
    case 0:
        return 0;
    default:
        wasp_format_breadth --;
    }
    
    if( ! wasp_format_depth ){
        wasp_string_append_cs( s, "..." );
        return 0;
    }

    wasp_format_depth --;

    wasp_type t = wasp_value_type( v );
    wasp_quad end_breadth = wasp_format_breadth;
    wasp_format_breadth = wasp_format_re_breadth;
    
    if( t && t->format ){
        t->format( s, v );
    }else{
        wasp_generic_format( s, v );
    }
    
    wasp_format_breadth = end_breadth;
    wasp_format_depth ++;
}

void wasp_format_value( 
    wasp_string s, wasp_value v, wasp_quad breadth, wasp_quad depth 
){
    //printf( "BREADTH: %i, DEPTH: %i\n", breadth, depth );
    wasp_format_depth = depth;
    wasp_format_breadth = breadth;
    wasp_format_re_breadth = breadth;
    wasp_format_item( s, v );
}

wasp_string wasp_formatf( char* fmt, ... ){
    va_list ap;
    wasp_string buf = wasp_make_string( 64 );
    va_start( ap, fmt );
    char* ptr = fmt;
    for(;;){
        switch( *(ptr++) ){
        case 's':
            wasp_string_append_cs( buf, va_arg( ap, const char* ) );
            break;
        case 'x':
            wasp_format_value( buf, va_arg( ap, wasp_value ), 32, 3 );
            break;
        case 'i':
            wasp_string_append_signed( buf, va_arg( ap, wasp_integer ) );
            break;
        case 'a':
            wasp_string_append_addr( buf, va_arg( ap, wasp_quad ) );
            break;
        case 'n':
            wasp_string_append_newline( buf );
        case 0:
            goto done;
        default:
            va_end( ap );
            wasp_errf( wasp_es_vm, "ss", 
                      "wasp_formatf cannot process format string", fmt );
        }
    }
done:
    va_end( ap );
    return buf;
}
