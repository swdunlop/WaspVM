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

// Some old BSD regexes require that sys/types.h be included first.
#include <sys/types.h>
#include <regex.h>

WASP_BEGIN_TYPE( regex )
    regex_t rx;
WASP_END_TYPE( regex )
#define REQ_REGEX_ARG( vn ) REQ_TYPED_ARG( vn, regex )
#define REGEX_RESULT( vn ) TYPED_RESULT( vn, regex )
#define OPT_REGEX_ARG( vn ) OPT_TYPED_ARG( vn, regex )

extern wasp_symbol wasp_es_rx;

wasp_regex wasp_make_regex( wasp_string pattern, const char* flagstr );
wasp_value  wasp_match_regex( wasp_regex regex, 
                            const char* str, const char* flagstr,
                            const char** head, const char** tail );

void wasp_init_regex_subsystem( );

#ifdef _WIN32
#include <malloc.h>
#endif

wasp_symbol wasp_es_rx;

int wasp_regex_error( wasp_regex regex, int code ){
    if( ! code )return 0;

    char errbuf[256];
    regerror( code, &( regex->rx ), errbuf, sizeof( errbuf ) );
    wasp_errf( wasp_es_rx, "s", errbuf );

    return code;
}

wasp_regex wasp_make_regex( wasp_string pattern, const char* flagstr ){
    int flags = REG_EXTENDED;
    if( flagstr ){
        for( ; *flagstr; flagstr++ )switch( *flagstr ){
        case 'b':
            if( flags & REG_EXTENDED ) flags ^= REG_EXTENDED;
            break;
        case 'i':
            flags |= REG_ICASE;
            break;
        case 'n':
            flags |= REG_NEWLINE;
            break;
        case 'm':
            flags |= REG_NOSUB;
            break;
        default:
            wasp_errf( wasp_es_rx, "s", "regex flag not recognized" );
        }
    }

    wasp_regex regex = WASP_OBJALLOC( regex );
    wasp_regex_error( regex, regcomp( &( regex->rx ), 
                     wasp_sf_string( pattern ), flags ) );
    return regex;
}

wasp_value  wasp_match_regex( wasp_regex regex, 
                           const char* str, const char* flagstr,
                           const char** head, const char** tail 
){
    int flags = 0;
    if( flagstr ){
        for( ; *flagstr; flagstr++ )switch( *flagstr ){
        case 'b':
            flags |= REG_NOTBOL;
            break;
        case 'e':
            flags |= REG_NOTEOL;
            break;
        default:
            wasp_errf( wasp_es_rx, "s", "regex flag not recognized" );
        }
    };

    int ct = regex->rx.re_nsub + 1;
    regmatch_t* mx = alloca( sizeof( regmatch_t ) * ct );
    int rs = regexec( &( regex->rx ), str, ct, mx, flags );
    if( rs == 0 ){
        const char* b = str + mx[0].rm_so;
        const char* e = str + mx[0].rm_eo;
        if( head ) (*head) = b;
        if( tail ) (*tail) = e;
        if( ct == 1 ){
            return wasp_vf_string( wasp_string_fm( b, e - b ) );
        }
        wasp_pair tc = wasp_make_tc( );
        int ix;
        for( ix = 1; ix < ct; ix ++ ){
            if( mx[ix].rm_so == -1 ){
                wasp_tc_append( tc, wasp_vf_false( ) );
            }else{
                b = str + mx[ix].rm_so;
                e = str + mx[ix].rm_eo;
                wasp_tc_append( 
                    tc, wasp_vf_string( wasp_string_fm( b, e - b ) ) 
                );
            }
        }
        return wasp_car( tc );
    }else if( rs == REG_NOMATCH ){
        return wasp_vf_false( );
    }else{
        wasp_regex_error( regex, rs );
    }
}


void wasp_free_regex( wasp_regex regex ){
    regfree( &( regex->rx ) );
    wasp_objfree( regex );
}

WASP_GENERIC_TRACE( regex );
WASP_GENERIC_COMPARE( regex );
WASP_GENERIC_FORMAT( regex );
WASP_C_TYPE( regex );

WASP_BEGIN_PRIM( "match-regex", match_regex )
    REQ_REGEX_ARG( regex );
    REQ_STRING_ARG( text );
    OPT_STRING_ARG( flags );
    NO_REST_ARGS( );
   
    RESULT( wasp_match_regex( regex, wasp_sf_string( text ), 
                                        has_flags ? wasp_sf_string( flags )
                                                  : NULL,
                                        NULL, NULL ) );
WASP_END_PRIM( match_regex )

WASP_BEGIN_PRIM( "match-regex*", match_regexm )
    REQ_REGEX_ARG( regex );
    REQ_STRING_ARG( text );
    OPT_STRING_ARG( flags );
    NO_REST_ARGS( );

    wasp_tc tc = wasp_make_tc( );
    const char* str = wasp_sf_string( text );
    const char* flagstr = has_flags ? wasp_sf_string( flags ) : NULL;
    wasp_boolean has_matched = 0;

    for(;;){
        const char* nxt;
        wasp_value m = wasp_match_regex( regex, str, flagstr, NULL, &nxt );
        if( wasp_is_false( m ) ) break;
        has_matched = 1;
        wasp_tc_append( tc, m );
        str = nxt;
    }
    
    RESULT( has_matched ? wasp_car( tc ) : wasp_vf_false( ) );
WASP_END_PRIM( match_regexm )

WASP_BEGIN_PRIM( "make-regex", make_regex )
    REQ_STRING_ARG( pattern );
    OPT_STRING_ARG( flags );
    NO_REST_ARGS( );

    RESULT( 
        wasp_vf_regex( wasp_make_regex( pattern, 
                                      has_flags ? wasp_sf_string( flags ) 
                                                : NULL ) ) 
    );
WASP_END_PRIM( make_regex )

WASP_BEGIN_PRIM( "string-read-regex!", string_read_regex )
    REQ_STRING_ARG( text );
    REQ_REGEX_ARG( regex );
    OPT_STRING_ARG( flags );

    NO_REST_ARGS( );
   
    const char* endp = NULL;
    const char* str = wasp_sf_string( text );
    const char* flagstr = has_flags ? wasp_sf_string( flags ) : NULL;
        
    wasp_value m = wasp_match_regex( regex, str, flagstr, NULL, &endp );

    if( ! wasp_is_false( m ) ){
        wasp_string_skip( text, endp - str );
    }

    RESULT( m );
WASP_END_PRIM( string_read_regex )

void wasp_init_regex_subsystem( ){
    WASP_I_TYPE( regex );
    wasp_es_rx = wasp_symbol_fs( wasp_regex_name );
    
    WASP_BIND_PRIM( make_regex );
    WASP_BIND_PRIM( match_regexm );
    WASP_BIND_PRIM( match_regex );
    WASP_BIND_PRIM( regexq );
    WASP_BIND_PRIM( string_read_regex );
}
