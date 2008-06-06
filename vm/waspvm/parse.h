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

// These expressions can parse a S-Expression, as defined by Mosquito Lisp;
// they do not do any pre-pass alteration of the contents, such as altering
// '(...) to (quote ...) or `(...) to (quasiquote ...).  

#ifndef WASP_PARSE_H
#define WASP_PARSE_H 1

#include "memory.h"

wasp_quad wasp_parse_dec( char** r_str, wasp_boolean* r_succ );
wasp_quad wasp_parse_hex( char** r_str, wasp_boolean* r_succ );
wasp_quad wasp_parse_hex2( char** r_str, wasp_boolean* r_succ );
wasp_integer wasp_parse_int( char** r_str, wasp_boolean* r_succ );

wasp_symbol wasp_parse_sym( char** r_str, wasp_boolean* r_succ );

wasp_string wasp_parse_str( char** r_str, wasp_boolean* r_succ );
wasp_list   wasp_parse_list( char** r_str, wasp_boolean* r_succ );
wasp_value  wasp_parse_value( char** r_str, wasp_boolean* r_succ );
wasp_list wasp_parse_document( char* doc, wasp_boolean* r_succ );

extern const char* wasp_parse_errmsg;
extern wasp_integer wasp_parse_incomplete;

void wasp_init_parse_subsystem( );

#endif
