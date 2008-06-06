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

#ifndef WASP_PACKAGE_H
#define WASP_PACKAGE_H

#include "memory.h"
#include "string.h"

wasp_value wasp_thaw_mem( const void* mem, wasp_quad len );
wasp_string wasp_freeze( wasp_value value );

static inline wasp_value wasp_thaw_str( wasp_string str ){
    return wasp_thaw_mem( wasp_sf_string( str ), wasp_string_length( str ) );
}
void wasp_init_package_subsystem();
wasp_pair wasp_thaw_tail( const char *name );

#endif
