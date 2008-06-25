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

#include <string.h>
#include <ctype.h>
#include "waspvm.h"

wasp_integer wasp_parse_incomplete = 0;
const char* wasp_parse_errmsg = NULL;
const char* wasp_em_nodigits = "expected digits";
const char* wasp_em_noprint = "illegal character";
const char* wasp_em_endq = "closing quote missing";
const char* wasp_em_endp = "closing \")\" missing";
const char* wasp_em_more = "expected more";
const char* wasp_em_nohead= "expected value before \".\"";
const char* wasp_em_notail = "expected value after \".\"";
const char* wasp_em_extra_tail = "superfluous value after \".\"";
const char* wasp_em_badsharp = "expected \"t\" or \"f\" after \"#\"";
const char* wasp_em_begp = "\")\" unmatched by \"(\"";
const char* wasp_em_baddot = "did not expect \".\"";

wasp_quad wasp_parse_dec( char** r_str, wasp_boolean* r_succ ){
    char* str = *r_str;
    wasp_quad result = 0;
    wasp_boolean any = 0;

    for(;;){
        char ch = *str;

        if(( ch >= '0' )&&( ch <= '9' )){
            result = result * 10 + ( ch - '0' );
        }else{
            break;
        }

        str++;
        any = 1;
    };

    if( any ){
        *r_succ = 1; 
        *r_str = str; 
    }else{
        wasp_parse_errmsg = wasp_em_nodigits;
        wasp_parse_incomplete = 1;
        *r_succ = 0; 
    }
    
    return result;
}

wasp_quad wasp_parse_hex2( char** r_str , wasp_boolean* r_succ ){
    char* str = *r_str;
    wasp_quad result = 0;
    int i = 2;

    while( i-- ){
        char ch = *str;

        if(( ch >= '0' )&&( ch <= '9' )){
            result = ( result << 4 ) | ( ch - '0' );
        }else if(( ch >= 'A' )&&( ch <= 'F' )){
            result = ( result << 4 ) | ( 10 + ch - 'A' );
        }else if(( ch >= 'a' )&&( ch <= 'f' )){
            result = ( result << 4 ) | ( 10 + ch - 'a' );
        }else{
            *r_succ = 0;
            wasp_parse_errmsg = wasp_em_nodigits;
            wasp_parse_incomplete = ch == 0;
            return 0;
        }
        
        str++;
    };

    *r_succ = 1; 
    *r_str = str; 
    
    return result;
}

wasp_quad wasp_parse_hex( char** r_str, wasp_boolean* r_succ ){
    char* str = *r_str;
    wasp_quad result = 0;
    wasp_boolean any = 0;

    for(;;){
        char ch = *str;

        if(( ch >= '0' )&&( ch <= '9' )){
            result = ( result << 4 ) | ( ch - '0' );
        }else if(( ch >= 'A' )&&( ch <= 'F' )){
            result = ( result << 4 ) | ( 10 + ch - 'A' );
        }else if(( ch >= 'a' )&&( ch <= 'f' )){
            result = ( result << 4 ) | ( 10 + ch - 'a' );
        }else{
            break;
        }
        
        str++;
        any = 1;
    };

    if( any ){
        *r_succ = 1; 
        *r_str = str; 
    }else{
        wasp_parse_errmsg = wasp_em_nodigits;
        wasp_parse_incomplete = 1;
        *r_succ = 0; 
    }
    
    return result;
}

wasp_integer wasp_parse_int( char** r_str, wasp_boolean* r_succ ){
    //TODO: Check for integer overflows.
    switch( **r_str ){
    case '$':
        (*r_str) ++; return wasp_parse_hex( r_str, r_succ );
    case '-':
        (*r_str) ++; return -1 * wasp_parse_dec( r_str, r_succ );
    case '+':
        (*r_str) ++;
    default:
        return wasp_parse_dec( r_str, r_succ );
    }
}

wasp_symbol wasp_parse_sym( char** r_str, wasp_boolean* r_succ ){
    char* str = *r_str;
    char* sym = str;
    
    char ch = *str;
    int any = 0;

    for(;;)switch( *str ){
    case ';':
    case '.':
    case ')':
    case ' ':
    case '\r':
    case '\n':
    case '\t':
    case '\0':
        goto done;
    default:
        if( ! isprint( ch ) ) goto done;
        any = 1;
        str++;
    }
done:
    *r_succ = any;
    *r_str = str;
    if( any ){
        return wasp_symbol_fm( sym, str - sym );
    }else{
        wasp_parse_errmsg = "expected symbol";
        wasp_parse_incomplete = 1;
        return NULL;
    }
}

wasp_string wasp_parse_str( char** r_str, wasp_boolean* r_succ ){
    char ch;
    char* str = *r_str;
    wasp_string buf = wasp_make_string( 64 );
    
    if( *str != '"' )goto fail;

    str++;

    for(;;){
        switch( ch = *str ){ 
        case 0: 
            wasp_parse_errmsg = wasp_em_endq;
        wasp_parse_incomplete = 1;
            goto fail;
        case '"': goto succ;
        case '\\':
            ch = *(++str);
            if( isdigit( ch ) ){
                wasp_boolean ok = 0;
                ch = wasp_parse_int( &str, &ok );
                // This should never fail.
                if( ! ok ) goto fail;
            }else{
                switch( ch ){
                case 0:
                    goto fail;
                case 'n':
                    ch = '\n';
                    break;
                case 'r':
                    ch = '\r';
                    break;
                case 't':
                    ch = '\t';
                    break;
                };
                str ++;
            };
            wasp_string_append( buf, &ch, 1 );
            break;
        default:
            wasp_string_append( buf, &ch, 1 );
            str ++;
        }
    }
succ:
    *r_succ = 1;
    *r_str = str + 1;

    return wasp_string_fm( wasp_string_head( buf ),
                          wasp_string_length( buf ) );
fail:
    *r_succ = 0;
    return NULL;
}

char* wasp_skip_space( char* str ){
    //TODO: Add skip comments code.
    for(;;){
        char ch = *str;
        if( isspace( ch ) ){
            str ++;
        }else if( ch == ';' ){
            // Sigh.. Comments.. Who comments, anymore?
            str ++;
            while( ! strchr( "\r\n", *str ) ) str ++;
        }else{
            break;
        }
    }
    return str;
}

wasp_list wasp_parse_list( char** r_str, wasp_boolean* r_succ ){
    char* str = *r_str;

    if( *str != '(' )goto fail;

    char ch;
    wasp_tc tc = wasp_make_tc( );
    wasp_string buf = wasp_make_string( 64 );
    wasp_value x;
    str++;

    for(;;){
        str = wasp_skip_space( str );
        switch( *str ){
        case '.':
            if( tc->head ){
                str = wasp_skip_space( str + 1 );
                if(( *str == '.' || *str == ')' )){
                    wasp_parse_errmsg = wasp_em_notail;
                    wasp_parse_incomplete = 0;
                    goto fail;
                }
                x = wasp_parse_value( &str, r_succ );

                if( *r_succ ){
                    wasp_set_cdr( tc->tail, x );
                    str = wasp_skip_space( str );
                    if( *str == ')' ){
                        str ++;
                        goto succ;
                    }else{
                        // More than one term follows '.' in a pair.
                        wasp_parse_errmsg = wasp_em_extra_tail;
                        wasp_parse_incomplete = 0;
                        
                        goto fail;
                    }
                }else{
                    // Parse value was displeased..
                    goto fail;
                };
            }else{
                // No term precedes '.' in the pair.
                wasp_parse_errmsg = wasp_em_nohead;
                wasp_parse_incomplete = 0;
                goto fail;
            }
        case ')':
            str ++;
            goto succ;
        case 0:
            wasp_parse_errmsg = wasp_em_endp;
            wasp_parse_incomplete = 1;
            goto fail;
        default:
            x = wasp_parse_value( &str, r_succ );
            if( *r_succ ){
                wasp_tc_add( tc, x );
            }else{
                // Parse value was displeased.
                goto fail;
            }
        }
    }    
succ:
    *r_succ = 1;
    *r_str = str;

    return tc->head;
fail:
    *r_succ = 0;
    return NULL;
}

wasp_symbol wasp_sym_scatter = NULL;
wasp_symbol wasp_sym_quote = NULL;
wasp_symbol wasp_sym_unquote = NULL;
wasp_symbol wasp_sym_quasiquote = NULL;

wasp_value wasp_parse_value_inner( char** r_str, wasp_boolean* r_succ ){
    wasp_value x;
    wasp_string s;
    wasp_symbol sym;

    char* str = *r_str;
    char ch = *str;

    switch( ch ){
    case 0:
        *r_succ = 0;
        wasp_parse_errmsg = wasp_em_more;
        wasp_parse_incomplete = 1;
        break;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '7':
    case '8':
    case '9':
    case '$':
        x = wasp_vf_integer( wasp_parse_int( &str, r_succ ) );
        break;
    case '@':
        str ++;
        x = wasp_vf_pair( wasp_listf( 2, wasp_sym_scatter,
                                       wasp_parse_value( &str, r_succ ) ) );
        break;
    case '`':
        str ++;
        x = wasp_vf_pair( wasp_listf( 2, wasp_sym_quasiquote,
                                       wasp_parse_value( &str, r_succ ) ) );
        break;
    case ',':
        str ++;
        x = wasp_vf_pair( wasp_listf( 2, wasp_sym_unquote,
                                       wasp_parse_value( &str, r_succ ) ) );
        break;
    case '\'': 
        str ++;
        x = wasp_vf_pair( wasp_listf( 2, wasp_sym_quote,
                                       wasp_parse_value( &str, r_succ ) ) );
        break;
    case '-':
    case '+':
        if( isdigit( *( str + 1 ) ) ){
            x = wasp_vf_integer( wasp_parse_int( &str, r_succ ) );
        }else{
            wasp_symbol s = wasp_parse_sym( &str, r_succ );
            if( *r_succ ) x = wasp_vf_symbol( s );
        }
        break;
    case '(':
        x = wasp_vf_list( wasp_parse_list( &str, r_succ ) );
        break;
    case '"':
        s = wasp_parse_str( &str, r_succ );
        if( *r_succ ) x = wasp_vf_string( s );
        break;
    case ')':
        *r_succ = 0;
        wasp_parse_incomplete = 0;
        wasp_parse_errmsg = wasp_em_begp;
        break;
    case '#':
        str ++;
        ch = *(str++);
        if( ch == 'f' ){
            *r_succ = 1;
            x = wasp_vf_false( );
        }else if( ch == 't' ){
            *r_succ = 1;
            x = wasp_vf_true( );
        }else{
            wasp_parse_errmsg = wasp_em_badsharp;
            wasp_parse_incomplete = ! ch;
        }
        break;
    default:
        sym = wasp_parse_sym( &str, r_succ );
        if( *r_succ ) x = wasp_vf_symbol( sym );
    }

    if( *r_succ ){
        *r_str = str;
        return x;
    }else{
        return wasp_vf_null();
    }
}

wasp_value wasp_parse_toplevel( char** r_str, wasp_boolean* r_succ ){
    *r_str = wasp_skip_space( *r_str );
    char ch = **r_str;
    if( ch == '.' ){
        r_succ = 0;
        wasp_parse_errmsg = wasp_em_baddot;
        wasp_parse_incomplete = 0;
    }else return wasp_parse_value_inner( r_str, r_succ ); 
}

wasp_value wasp_parse_value( char** r_str, wasp_boolean* r_succ ){
    *r_str = wasp_skip_space( *r_str );
    return wasp_parse_value_inner( r_str, r_succ );
}

wasp_list wasp_parse_document( char* doc, wasp_boolean* r_succ ){
    wasp_tc tc = wasp_make_tc( );
    wasp_parse_errmsg = NULL;
    wasp_parse_incomplete = 0;
    for(;;){
        doc = wasp_skip_space( doc );
        if( *doc ){
            wasp_value x = wasp_parse_toplevel( &doc, r_succ );
            if( *r_succ ){
                wasp_tc_add( tc, x );
            }else{
                goto fail;
            }
        }else break;
    }
succ:
    *r_succ = 1;
    return tc->head;
fail:
    *r_succ = 0;
    return NULL;
}

void wasp_init_parse_subsystem( ){
    wasp_sym_scatter = wasp_symbol_fs( "scatter" );
    wasp_sym_quote = wasp_symbol_fs( "quote" );
    wasp_sym_unquote = wasp_symbol_fs( "unquote" );
    wasp_sym_quasiquote = wasp_symbol_fs( "quasiquote" );
}
