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

#ifndef WASP_STRING_H
#define WASP_STRING_H 1

#include "memory.h"

// The string Type provides a expansible memory object that works well 
// for I/O buffers, and strings. 
//
WASP_BEGIN_TYPE( string ) 
    wasp_integer origin, length, capacity; 
    char* pool; 
WASP_END_TYPE( string ) 

#define REQ_STRING_ARG( vn ) REQ_TYPED_ARG( vn, string )
#define STRING_RESULT( vn ) TYPED_RESULT( string, vn )
#define OPT_STRING_ARG( vn ) OPT_TYPED_ARG( vn, string )

WASP_BEGIN_TYPE( symbol )
    wasp_string  string;
    wasp_value   value;
    wasp_boolean global;
WASP_END_TYPE( symbol )

#define REQ_SYMBOL_ARG( vn ) REQ_TYPED_ARG( vn, symbol )
#define SYMBOL_RESULT( vn ) TYPED_RESULT( vn, symbol )
#define OPT_SYMBOL_ARG( vn ) OPT_TYPED_ARG( vn, symbol )

static inline wasp_quad wasp_string_length( wasp_string string ){ 
    return string->length; 
}

wasp_value wasp_lexicon_key( wasp_value item );
wasp_symbol wasp_symbol_fm( const void* s, wasp_integer sl );
wasp_symbol wasp_symbol_fs( const char* s );
wasp_string wasp_make_string( wasp_integer capacity );
wasp_integer wasp_string_compare( wasp_string a, wasp_string b );
wasp_boolean wasp_eqvs( wasp_string a, wasp_string b );
wasp_boolean wasp_has_global( wasp_symbol name );
void wasp_set_global( wasp_symbol name, wasp_value value );
wasp_value wasp_get_global( wasp_symbol name );
void wasp_format_string( wasp_string buf, wasp_string str );

wasp_list wasp_get_globals( );
void wasp_init_string_subsystem( );
void wasp_compact_string( wasp_string string );
void wasp_string_expand( wasp_string string, wasp_integer count );
void wasp_string_flush( wasp_string string );
void wasp_string_append( wasp_string string, const void* src, wasp_integer srclen );
void wasp_string_alter( 
    wasp_string string, wasp_integer dstofs, wasp_integer dstlen, 
    const void* src, wasp_integer srclen
);
char* wasp_sf_string( wasp_string string );
void wasp_string_skip( wasp_string string, wasp_integer offset );
void* wasp_string_read( wasp_string string, wasp_integer* r_count );
void* wasp_string_read_line( wasp_string string, wasp_integer* r_count );
wasp_string wasp_string_fm( const void* s, wasp_integer sl );
wasp_string wasp_string_fs( const char* s );
void wasp_string_prepend( wasp_string string, const void* src, wasp_integer srclen );
void wasp_string_append_byte( wasp_string string, wasp_byte x );
void wasp_string_append_byte( wasp_string string, wasp_byte x );
void wasp_string_append_word( wasp_string string, wasp_word x );
void wasp_string_append_quad( wasp_string string, wasp_quad x );
void* wasp_string_head( wasp_string head );
void* wasp_string_tail( wasp_string head );
void wasp_string_wrote( wasp_string string, wasp_integer len );
void wasp_string_skip( wasp_string string, wasp_integer offset );
wasp_boolean wasp_string_empty( wasp_string str );

void wasp_string_append_newline( wasp_string buf );
void wasp_string_append_hexnibble( wasp_string buf, wasp_quad digit );
void wasp_string_append_hexbyte( wasp_string buf, wasp_quad byte );
void wasp_string_append_hexword( wasp_string buf, wasp_quad word );
void wasp_string_append_hexquad( wasp_string buf, wasp_quad word );
void wasp_string_append_indent( wasp_string buf, wasp_integer depth );
void wasp_string_append_unsigned( wasp_string str, wasp_quad number );
void wasp_string_append_signed( wasp_string str, wasp_integer number );
void wasp_string_append_hex( wasp_string str, wasp_quad number );
void wasp_string_append_str( wasp_string buf, wasp_string s );
void wasp_string_append_sym( wasp_string buf, wasp_symbol s );
void wasp_string_append_addr( wasp_string buf, wasp_integer i );
void wasp_string_append_cs( wasp_string buf, const char* c );
void wasp_string_append_exprs( wasp_string str, wasp_list list );
wasp_string wasp_exprs_to_string( wasp_list exprs );

wasp_string wasp_reads_string( wasp_string string );

#endif
