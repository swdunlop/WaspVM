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

#ifndef WASP_PRINT_H
#define WASP_PRINT_H 1

#include "memory.h"

void wasp_printmem( const void* mem, wasp_integer len );
void wasp_print( const char* st );
void wasp_printch( wasp_byte ch );
void wasp_printstr( wasp_string s );
void wasp_newline( );
void wasp_space( );
void wasp_show( wasp_value v );
void wasp_init_print_subsystem( );

#endif
