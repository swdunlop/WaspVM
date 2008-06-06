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

#ifndef WASP_FORMAT_H
#define WASP_FORMAT_H

#include "memory.h"
#include <stdarg.h>

void wasp_format_begin( wasp_string buf, void* o );
void wasp_format_end( wasp_string buf );
int wasp_format_item( wasp_string s, wasp_value v );
void wasp_format_value( 
    wasp_string s, wasp_value v, wasp_quad breadth, wasp_quad depth 
);
wasp_string wasp_formatf( char* fmt, ... );

#define wasp_printf( fmt, ... ) wasp_printstr( wasp_formatf( fmt, __VA_ARGS__ ) );

#endif

