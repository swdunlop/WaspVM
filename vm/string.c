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
#include <string.h>
#include <ctype.h>

#ifdef WASP_IN_MINGW
// We need hton and ntoh
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#ifdef AUDIT_STRINGS
#define AUDIT_STRING( x ) wasp_audit_string( x );
void wasp_audit_string( wasp_string string ){
    assert( string );
    assert( string->pool );
    assert( string->length <= string->capacity );
    assert( string->origin <= string->capacity );
    assert(( string->origin + string->length ) <= string->capacity );
    assert( string->origin < 32767 );
    assert( string->length < 32767 );
    assert( string->capacity < 32767 );
    assert( string->origin < 32767 );
    assert( string->length < 32767 );
    assert( string->capacity < 32767 );
}
#else
#define AUDIT_STRING( x ) ;
#endif

wasp_value wasp_lexicon_key( wasp_value item ){
    return wasp_vf_string( wasp_symbol_fv( item )->string );
}

extern struct wasp_type_data wasp_tree_type_data;

struct wasp_tree_data wasp_lexicon_data = { 
    { &wasp_tree_type_data },
    (wasp_node)NULL, 
    wasp_lexicon_key 
};

wasp_tree wasp_lexicon = &wasp_lexicon_data;

wasp_symbol wasp_symbol_fm( const void* s, wasp_integer sl ){
    wasp_symbol sym;
    wasp_string str;
    wasp_node node; 

    str = wasp_string_fm( s, sl );
    AUDIT_STRING( str );
    node = wasp_tree_lookup( wasp_lexicon, wasp_vf_string( str ) );

    if( node ){ 
        wasp_objfree( str );
        return wasp_symbol_fv( node->data ); 
    }else{
        sym = WASP_OBJALLOC( symbol );
        sym->string = str;
        sym->global = 0;
        sym->value = wasp_vf_null();
        //TODO: ldg and stg must respect global.
        wasp_tree_insert( wasp_lexicon, wasp_vf_symbol( sym ) );
        return sym;
    }
}
wasp_symbol wasp_symbol_fs( const char* s ){
    return wasp_symbol_fm( s, strlen( s ) );
}

wasp_string wasp_make_string( wasp_integer capacity ){
    wasp_string string = WASP_OBJALLOC( string );
    string->pool = malloc( capacity + 1 );
    string->capacity = capacity;
    AUDIT_STRING( string );
    return string;
}

wasp_integer wasp_string_compare( wasp_string a, wasp_string b ){
    //This will result in dictionary-style ordering of strings,
    //with case sensitivity.
    //
    //NOTE: Ideally, we would also use a string hash here to
    //      give us a second form of equality testing prior
    //      to degenerating into memcmp, but there's a point
    //      where performance optimizations must give way to
    //      code complexity.

    wasp_quad al = wasp_string_length( a );
    wasp_quad bl = wasp_string_length( b );
    wasp_integer d = memcmp( wasp_sf_string( a ), 
                            wasp_sf_string( b ),
                            al < bl ? al : bl );

    return d ? d : ( al - bl );
}

wasp_boolean wasp_has_global( wasp_symbol name ){
    return name->global;    
}

void wasp_set_global( wasp_symbol name, wasp_value value ){
    name->value = value;
    name->global = 1;
}

wasp_value wasp_get_global( wasp_symbol name ){
    return wasp_has_global( name ) ? name->value : wasp_vf_null();
}

void wasp_format_string( wasp_string buf, wasp_string str ){
    //TODO: Improve with ellision, scored length.
    AUDIT_STRING( str );
    wasp_string_append_byte( buf, '"' );
    const char* ptr = wasp_string_head( str );
    wasp_integer i, len = wasp_string_length( str );
    for( i =0; i < len; i ++ ){
        unsigned char ch = *(ptr + i );
        switch( ch ){
        case '\r':
            wasp_string_append_cs( buf, "\\r" );
            break;
        case '\n':
            wasp_string_append_cs( buf, "\\n" );
            break;
        case '\t':
            wasp_string_append_cs( buf, "\\t" );
            break;
        case '"':
            wasp_string_append_cs( buf, "\\\"" );
            break;
        default:
            if( isprint( ch ) ){
                wasp_string_append_byte( buf, ch );
            }else{
                wasp_string_append_byte( buf, '\\' );
                wasp_string_append_unsigned( buf, ch );
            }
        }
    };
    wasp_string_append_byte( buf, '"' );
}

WASP_GENERIC_TRACE( string );
void wasp_free_string( wasp_string str ){
    AUDIT_STRING( str );
    free( str->pool );
    wasp_objfree( (wasp_object) str );
}
WASP_C_TYPE( string );

void wasp_trace_symbol( wasp_symbol symbol ){
    AUDIT_STRING( symbol->string );
    wasp_grey_obj( (wasp_object) symbol->string );
    if( symbol->global )wasp_grey_val( symbol->value );    
}
void wasp_format_symbol( wasp_string buf, wasp_symbol sym ){
    wasp_string_append_sym( buf, sym ); 
}
void wasp_free_symbol( wasp_symbol sym ){
    assert( 0 );
    wasp_objfree( (wasp_object) sym );
}
// WASP_GENERIC_FREE( symbol);
WASP_GENERIC_COMPARE( symbol);
WASP_C_TYPE( symbol );

void wasp_globals_iter( wasp_value data, wasp_tc tc ){
    wasp_symbol sym = wasp_symbol_fv( data );
    if( wasp_has_global( sym ) ){ 
        wasp_tc_add( tc, wasp_vf_pair( wasp_cons( wasp_vf_symbol( sym ),
                                                  wasp_get_global( sym ) ) ) );
    }
}
wasp_list wasp_get_globals( ){
    wasp_tc tc = wasp_make_tc( );
    wasp_iter_tree( wasp_lexicon, (wasp_iter_mt)wasp_globals_iter, tc );
    return tc->head;
}
void wasp_init_string_subsystem( ){
    wasp_root_obj( (wasp_object)wasp_lexicon );
    WASP_I_TYPE( string );
    WASP_I_TYPE( symbol );
}
void wasp_compact_string( wasp_string str ){
    AUDIT_STRING( str );
    if( str->origin ){
        if( str->length ){
            memmove( str->pool, 
                    str->pool + str->origin, 
                    str->length );
            str->pool[str->length + 1] = 0;
        };
        str->origin = 0;
    };
    AUDIT_STRING( str );
}
void wasp_string_expand( wasp_string string, wasp_integer newlen ){
    AUDIT_STRING( string );
    wasp_integer incr = newlen - string->length;
    if( incr < 0 )return;

    wasp_integer head = string->origin;

    wasp_integer tail = string->capacity - head - string->length;
    if( tail > incr )return;

    wasp_compact_string( string );

    if(( tail + head )> incr )return;
    
    wasp_integer newcap = string->capacity + 1; 

    while( newcap < newlen ) newcap <<= 1;

    string->pool = realloc( string->pool, newcap + 1 );
    string->capacity = newcap;
    
    AUDIT_STRING( string );
}
void wasp_string_flush( wasp_string string ){
    AUDIT_STRING( string );
    string->pool[ string->origin = string->length = 0 ] = 0;
    AUDIT_STRING( string );
}
void wasp_string_alter( 
    wasp_string string, wasp_integer dstofs, wasp_integer dstlen, 
    const void* src, wasp_integer srclen
){
    //TODO: This is still naive -- there are situations where the head could
    //      be moved upwards, and the tail moved downwards, without needing
    //      to totally alter the string.
    
    AUDIT_STRING( string );
    wasp_integer newlen = string->length + srclen - dstlen;

    wasp_string_expand( string, newlen );
    
    void* dst = string->pool + string->origin + dstofs;

    void* tail = dst + dstlen;
    wasp_integer taillen = string->length - dstlen - dstofs;

    void* newtail = dst + srclen;
    
    if( taillen && ( tail != newtail ))memmove( dst + srclen, tail, taillen );
    if( srclen ) memmove( dst, src, srclen );

    string->length = newlen;
    string->pool[ string->origin + newlen ] = 0;
    AUDIT_STRING( string );
}
void wasp_string_prepend( 
    wasp_string string, const void* src, wasp_integer srclen
){
    if( srclen < string->origin ){
        string->origin -= srclen;
        string->length += srclen;
        memmove( string->pool + string->origin, src, srclen );
    }else{
        wasp_string_alter( string, 0, 0, src, srclen );
    }
}
void wasp_string_append(
    wasp_string string, const void* src, wasp_integer srclen 
){
    wasp_integer endpos = string->length + string->origin;

    if( srclen < ( string->capacity - endpos ) ){
        string->length += srclen;
        memmove( string->pool + endpos, src, srclen );
    }else{
        wasp_string_alter( string, string->length, 0, src, srclen );
    }
}
char* wasp_sf_string( wasp_string string ){
    string->pool[ string->origin + string->length ] = 0;
    return string->pool + string->origin;
}
void wasp_string_skip( wasp_string string, wasp_integer offset ){
    assert( string->length >= offset );
    
    string->length -= offset;
    string->origin += offset;
}
void* wasp_string_read( wasp_string string, wasp_integer* r_count ){
    wasp_integer count = *r_count;
    void* pool = wasp_sf_string( string );
    if( count > string->length ) count = string->length;
    string->length -= count;
    string->origin += count;

    *r_count = count;
    return pool;
}
void* wasp_string_read_line( wasp_string string, wasp_integer* r_count ){
    char* line = wasp_sf_string( string );
    wasp_integer linelen = string->length;
    wasp_integer seplen = 0;
    wasp_integer index = 0;

    while( index < linelen ){
        if( line[ index ] == '\n' ){
            linelen = index;
            seplen = 1;
            goto complete;
        }else if( line[ index ] == '\r' ){
            linelen = index;
            seplen = ( line[ index + 1 ] == '\n' ) ? 2 : 1;
            goto complete;
        }else{
            index ++;
        }
    }
incomplete:
    return NULL;
complete:
    string->origin += linelen + seplen;
    string->length -= linelen + seplen;
    *r_count = linelen;
    return line;
}
wasp_string wasp_string_fm( const void* s, wasp_integer sl ){
    wasp_string a = wasp_make_string( sl );
    memcpy( a->pool, s, sl );
    a->pool[sl] = 0;
    a->length = sl;
    return a;
}
wasp_string wasp_string_fs( const char* s ){
    return wasp_string_fm( (const void*)s, strlen( s ) );
}
void wasp_string_append_byte( wasp_string string, wasp_byte x ){
    wasp_string_append( string, &x, 1 );
    AUDIT_STRING( string );
}
void wasp_string_append_word( wasp_string string, wasp_word x ){
    x = htons( x );
    wasp_string_append( string, &x, 2 );
    AUDIT_STRING( string );
}
void wasp_string_append_quad( wasp_string string, wasp_quad x ){
    x = htonl( x );
    wasp_string_append( string, &x, 4 );
    AUDIT_STRING( string );
}
void* wasp_string_head( wasp_string head ){
    AUDIT_STRING( head );
    return head->pool + head->origin;
}
void* wasp_string_tail( wasp_string string ){
    AUDIT_STRING( string );
    return string->pool + string->origin + string->length;
}
void wasp_string_wrote( wasp_string string, wasp_integer len ){
    AUDIT_STRING( string );
    string->length += len;
}
wasp_boolean wasp_string_empty( wasp_string str ){
    AUDIT_STRING( str );
    return ! str->length;
}
void wasp_string_append_newline( wasp_string buf ){
#ifdef WASP_IN_WIN32 
    wasp_string_append_cs( buf, "\r\n" );
#else
    wasp_string_append_byte( buf, '\n' );
#endif
}

void wasp_string_append_hexnibble( wasp_string buf, wasp_quad digit ){
    if( digit > 9 ){
        wasp_string_append_byte( buf, 'A' + digit - 10 );
    }else{
        wasp_string_append_byte( buf, '0' + digit );
    }
}

void wasp_string_append_hexbyte( wasp_string buf, wasp_quad byte ){
    wasp_string_append_hexnibble( buf, byte / 16 );
    wasp_string_append_hexnibble( buf, byte % 16 );
}
void wasp_string_append_hexword( wasp_string buf, wasp_quad word ){
    wasp_string_append_hexbyte( buf, word / 256 );
    wasp_string_append_hexbyte( buf + 2, word % 256 );
}
void wasp_string_append_hexquad( wasp_string buf, wasp_quad word ){
    wasp_string_append_hexword( buf, word / 65536 );
    wasp_string_append_hexword( buf + 4, word % 65536 );
}
void wasp_string_append_indent( wasp_string buf, wasp_integer depth ){
    while( ( depth-- ) > 0 ) wasp_string_append_byte( buf, ' ' );
}
void wasp_string_append_unsigned( wasp_string str, wasp_quad number ){
    static char buf[256];
    buf[255] = 0;
    int i = 255;

    do{
        buf[ --i ] = '0' + number % 10;
    }while( number /= 10 );
   
    wasp_string_append( str, buf + i, 255 - i );
};
void wasp_string_append_signed( wasp_string str, wasp_integer number ){
    if( number < 0 ){
        wasp_string_append_byte( str, '-' );
        number = -number;
    }
    wasp_string_append_unsigned( str, number );
}
void wasp_string_append_hex( wasp_string str, wasp_quad number ){
    static char buf[256];
    buf[255] = 0;
    int i = 255;
    
    do{
        int digit = number % 16;
        if( digit > 9 ){
            buf[ -- i ] = 'A' + digit - 10;
        }else{
            buf[ --i ] = '0' + digit;
        }
    }while( number /= 16 );
   
    wasp_string_append( str, buf + i, 255 - i ); 
}
void wasp_string_append_str( wasp_string buf, wasp_string s ){
    wasp_string_append( buf, wasp_sf_string( s ), wasp_string_length( s ) );
}
void wasp_string_append_sym( wasp_string buf, wasp_symbol s ){
    wasp_string_append_str( buf, s->string );
}
void wasp_string_append_addr( wasp_string buf, wasp_integer i ){
    //TODO: Replace.
    if( i ){
        wasp_string_append_hex( buf, (wasp_quad)i );
    }else{
        wasp_string_append_cs( buf, "null" );
    }
}
void wasp_string_append_cs( wasp_string buf, const char* c ){
    wasp_string_append( buf, c, strlen( c ) );
}


wasp_string wasp_reads_string( wasp_string string ){
    unsigned int len = WASP_MAX_IMM;
    const char* str = wasp_string_read( string, &len );
    return wasp_string_fm( str, len );
}

void wasp_string_append_expr( wasp_string str, wasp_value expr ){
    if( wasp_is_null( expr ) ){
        wasp_string_append_cs( str, "()" );
    }else if( wasp_is_string( expr ) ){
        wasp_format_string( str, wasp_string_fv( expr ) );
    }else if( wasp_is_symbol( expr ) ){
        wasp_format_symbol( str, wasp_symbol_fv( expr ) );
    }else if( wasp_is_integer( expr ) ){
        wasp_string_append_signed( str, wasp_integer_fv( expr ) );
    }else if( wasp_is_boolean( expr ) ){
        wasp_format_boolean( str, expr );
    }else if( wasp_is_pair( expr ) ){
        wasp_string_append_byte( str, '(' );
        wasp_pair p = wasp_pair_fv( expr );
        for(;;){
            wasp_string_append_expr( str, wasp_car( p ) );
            wasp_value v = wasp_cdr( p );
            if( wasp_is_pair( v ) ){
                p = wasp_pair_fv( v );
                wasp_string_append_byte( str, ' ' );
            }else if( wasp_is_null( v ) ){
                wasp_string_append_byte( str, ')' );
                return;
            }else{
                wasp_string_append_cs( str, " . " );
                wasp_string_append_expr( str, v );
                wasp_string_append_byte( str, ')' );
                return;
            }
        }
    }else{
        wasp_errf( wasp_es_vm, "sx", "cannot convert expression to lisp term", expr );
    }
}

void wasp_string_append_exprs( wasp_string str, wasp_list list ){
    if( list == NULL ) return;
    wasp_pair p = list;
    
    for(;;){
        wasp_string_append_expr( str, wasp_car( p ) );
        wasp_string_append_newline( str );

        wasp_value v = wasp_cdr( p );
        if( wasp_is_pair( v ) ){
            p = wasp_pair_fv( v );
        }else if( wasp_is_null( v ) ){
            return;
        }else{
            wasp_errf( wasp_es_vm, "sxx", "last pair cdr is not null", list, v );
        }
    };
}

wasp_string wasp_exprs_to_string( wasp_list exprs ){
    wasp_string str = wasp_make_string( 256 );
    wasp_string_append_exprs( str, exprs );
    return str;
}

wasp_value wasp_string_read_value( wasp_string string ){
    char* begin = wasp_sf_string( string );
    char* end = begin;
    wasp_boolean succ = 0;
    wasp_value result = wasp_parse_toplevel( &end, &succ );
    if( succ ){
        wasp_string_skip( string, end - begin );
        return result;
    }else{
        wasp_errf( wasp_es_vm, "sxx", 
                   wasp_parse_errmsg, string, 
                   wasp_vf_boolean( wasp_parse_incomplete ) 
        );
    }
}
