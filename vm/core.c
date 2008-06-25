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
#include <unistd.h>
#include <ctype.h>
#include <sys/param.h>
#include <errno.h>

#ifdef WASP_IN_MINGW
// We need hton and ntoh
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

WASP_BEGIN_PRIM( "string-read-expr!", string_read_expr )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    RESULT( wasp_string_read_value( string ) );
WASP_END_PRIM( string_read_expr )

WASP_BEGIN_PRIM( "exprs->string", exprs_to_string )
    REQ_LIST_ARG( exprs );
    NO_REST_ARGS( );
    STRING_RESULT( wasp_exprs_to_string( exprs ) );
WASP_END_PRIM( exprs_to_string )

WASP_BEGIN_PRIM( "xml-escape", xml_escape )
    REQ_STRING_ARG( data );
    NO_REST_ARGS( );
    
    const char* src = wasp_sf_string( data );
    int ix, srclen = wasp_string_length( data );
    wasp_string result = wasp_make_string( srclen );
    
    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        switch( ch ){
        case '\'':
            wasp_string_append_cs( result, "&apos;" );
            break;
        case '"':
            wasp_string_append_cs( result, "&quot;" );
            break;
        case '&':
            wasp_string_append_cs( result, "&amp;" );
            break;
        case '<':
            wasp_string_append_cs( result, "&lt;" );
            break;
        case '>':
            wasp_string_append_cs( result, "&gt;" );
            break;
        default:
            wasp_string_append_byte( result, ch );
        };
    }
    
    RESULT( wasp_vf_string( result ) );
WASP_END_PRIM( xml_escape )

WASP_BEGIN_PRIM( "percent-encode", percent_encode )
    REQ_STRING_ARG( data );
    REQ_STRING_ARG( mask );
    NO_REST_ARGS( );
    
    char* maskstr = wasp_sf_string( mask );

    const char* src = wasp_sf_string( data );
    int ix, srclen = wasp_string_length( data );
    wasp_string result = wasp_make_string( srclen );
    
    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        if( ch == '%' || strchr( maskstr, ch ) ){
            wasp_string_append_byte( result, '%' );
            wasp_string_append_hex( result, ch );
        }else{
            wasp_string_append_byte( result, ch );
        }
    }
    
    RESULT( wasp_vf_string( result ) );
WASP_END_PRIM( percent_encode )

WASP_BEGIN_PRIM( "percent-decode", percent_decode )
    REQ_STRING_ARG( data );
    NO_REST_ARGS( );

    char* src = wasp_sf_string( data );
    int srclen = wasp_string_length( data );
    wasp_string result = wasp_make_string( srclen );
    char ch;

    while( ch = *src ){
        src ++;
        if( ch == '%' ){
            wasp_boolean ok = 1;
            ch = (unsigned char)wasp_parse_hex2( &src, &ok );
            if( ! ok )wasp_errf( wasp_es_vm, "sxs", "invalid escape", data, src );
        }
        wasp_string_append_byte( result, ch );
    }
    
    RESULT( wasp_vf_string( result ) );
WASP_END_PRIM( percent_decode )

void wasp_untree_cb( wasp_value value, wasp_tc tc ){
    wasp_tc_add( tc, value );
}

WASP_BEGIN_PRIM( "string->integer", string_to_integer )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( )
    
    char* hd = wasp_sf_string( string );
    char* pt = hd;
    int ok = 0;

    wasp_integer i = wasp_parse_int( &pt, &ok );

    if( ! ok ){
        wasp_errf( wasp_es_vm, "s", "could not parse integer" );
    }else if( ( pt - hd ) != wasp_string_length( string ) ){
        wasp_errf( wasp_es_vm, "ss", "garbage trails integer", hd );
    }
    RESULT( wasp_vf_integer( i ) );
WASP_END_PRIM( string_to_integer )

WASP_BEGIN_PRIM( "vector->list", vector_to_list )
    REQ_VECTOR_ARG( v );
    NO_REST_ARGS( );
     
    wasp_pair p = NULL;
    wasp_quad l = wasp_vector_length( v );
    
    while( l ){
        p = wasp_cons( wasp_vector_get( v, --l ), wasp_vf_list( p ) );
    }

    LIST_RESULT( p );
WASP_END_PRIM( vector_to_list )

WASP_BEGIN_PRIM( "list->vector", list_to_vector )
    REQ_LIST_ARG( p );
    NO_REST_ARGS( );
     
    wasp_vector v = wasp_make_vector( wasp_list_length( p ) ); 
    wasp_quad i = 0;

    while( p ){
        wasp_vector_put( v, i++, wasp_car( p ) );
        p = wasp_req_list( wasp_cdr( p ) );
    }
    
    RESULT( wasp_vf_vector( v ) );
WASP_END_PRIM( list_to_vector )

WASP_BEGIN_PRIM( "cadr", cadr )
    REQ_PAIR_ARG( pair )
    NO_REST_ARGS( )
    
    pair = wasp_req_pair( wasp_cdr( pair ) );

    RESULT( wasp_car( pair ) );
WASP_END_PRIM( cadr );

WASP_BEGIN_PRIM( "reverse", reverse )
    REQ_LIST_ARG( pair );
    NO_REST_ARGS( )
    
    wasp_pair ep = NULL;
    while( pair ){
        ep = wasp_cons( wasp_car( pair ), wasp_vf_list( ep ) );
        pair = wasp_req_list( wasp_cdr( pair ) );
    }
    RESULT( wasp_vf_list( ep ) );
WASP_END_PRIM( reverse );

WASP_BEGIN_PRIM( "reverse!", reversed )
    REQ_LIST_ARG( pair );
    NO_REST_ARGS( )
    
    wasp_pair ep = NULL;
    wasp_pair next;
    while( pair ){
        next = wasp_req_list( wasp_cdr( pair ) );
        wasp_set_cdr( pair, wasp_vf_pair( ep ) );
        ep = pair;
        pair = next;
    }
    RESULT( wasp_vf_list( ep ) );
WASP_END_PRIM( reversed );

WASP_BEGIN_PRIM( "caddr", caddr )
    REQ_PAIR_ARG( pair )
    NO_REST_ARGS( )
    
    pair = wasp_req_pair( wasp_cdr( pair ) );
    pair = wasp_req_pair( wasp_cdr( pair ) );

    RESULT( wasp_car( pair ) );
WASP_END_PRIM( caddr );

WASP_BEGIN_PRIM( "equal?", equalq )
    REQ_ANY_ARG( v0 );
    for(;;){
        OPT_ANY_ARG( vN );
        if( ! has_vN )break;
        if( wasp_cmp_eq( v0, vN ) ){
            RESULT( wasp_vf_false( ) );
        }
    }
    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( equalq );

WASP_BEGIN_PRIM( "not", not )
    REQ_ANY_ARG( value )
    NO_REST_ARGS( );
    
    RESULT( wasp_vf_boolean( wasp_is_false( value ) ) );
WASP_END_PRIM( not )

WASP_BEGIN_PRIM( "last-pair", last_pair )
    REQ_LIST_ARG( list )
    NO_REST_ARGS( );
    RESULT( wasp_vf_pair( wasp_last_pair( list ) ) ); 
WASP_END_PRIM( last_pair )

WASP_BEGIN_PRIM( "last-item", last_item )
    REQ_LIST_ARG( list )
    NO_REST_ARGS( );
    RESULT( wasp_car( wasp_last_pair( list ) ) ); 
WASP_END_PRIM( last_item )

WASP_BEGIN_PRIM( "list-ref", list_ref )
    REQ_PAIR_ARG( list );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );
    
    RESULT( wasp_car( wasp_list_ref( list, index ) ) );
    /*
    while( list && index > 0 ){
        index --; list = wasp_req_list( wasp_cdr( list ));
    }
    if( list == NULL )wasp_errf( wasp_es_vm, "s", "index past end of list" );
    RESULT( wasp_car( list ) );
    */
WASP_END_PRIM( list_ref )

WASP_BEGIN_PRIM( "list-refp", list_refp )
    REQ_PAIR_ARG( list );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );

    LIST_RESULT( wasp_list_ref( list, index ) );
WASP_END_PRIM( list_refp )

WASP_BEGIN_PRIM( "abs", m_abs )
    REQ_INTEGER_ARG( integer );
    NO_REST_ARGS( );
    
    RESULT( wasp_vf_integer( integer < 0 ?  -integer : integer ) );
WASP_END_PRIM( m_abs )

WASP_BEGIN_PRIM( "*", m_mul )
    REQ_INTEGER_ARG( v0 );
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        v0 *= vN;
    };
    RESULT( wasp_vf_integer( v0 ) );
WASP_END_PRIM( m_mul )

WASP_BEGIN_PRIM( "/", m_div )
    REQ_INTEGER_ARG( v0 );
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( ! vN )wasp_errf( wasp_es_vm, "s", "attempted divide by zero" );
        v0 /= vN;
    };
    RESULT( wasp_vf_integer( v0 ) );
WASP_END_PRIM( m_div )

WASP_BEGIN_PRIM( "quotient", quotient )
    REQ_INTEGER_ARG( n1 );
    REQ_INTEGER_ARG( n2 );
    NO_REST_ARGS( );

    if(! n2 ){
        wasp_errf( wasp_es_vm, "s", "attempted divide by zero" );
    }
    RESULT( wasp_vf_integer( n1 / n2 ) );
WASP_END_PRIM( quotient )

WASP_BEGIN_PRIM( "remainder", remainder )
    REQ_INTEGER_ARG( n1 );
    REQ_INTEGER_ARG( n2 );
    NO_REST_ARGS( );

    if(! n2 ){
        wasp_errf( wasp_es_vm, "s", "attempted divide by zero" );
    }
    RESULT( wasp_vf_integer( n1 % n2 ) );
WASP_END_PRIM( remainder )

WASP_BEGIN_PRIM( "number->string", number_to_string )
    /* "Time they say is the great healer, but I believe in chemicals, baby."
     * -- Fatboy Slim, "Push and Shove" */

    /* There is precisely one way to output a number in base 10 in the standard
       C library. But I'll be damned if I'll use sprintf. */
    REQ_INTEGER_ARG( number );
    NO_REST_ARGS( );
    
    //TODO: format / print / redundant

    static char buf[256];
    buf[255] = 0;
    int i = 255;
    int neg = number < 0;
    if( neg ){ number = -number; };

    do{
        buf[ --i ] = '0' + number % 10;
    }while( number /= 10 );

    if( neg )buf[ -- i ] = '-';

    RESULT( wasp_vf_string( wasp_string_fm( buf + i, 255 - i ) ) );
WASP_END_PRIM( number_to_string );

WASP_BEGIN_PRIM( "string->symbol", string_to_symbol )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );
    RESULT( wasp_vf_symbol( wasp_symbol_fs( wasp_sf_string( string ) ) ) );
WASP_END_PRIM( string_to_symbol );

WASP_BEGIN_PRIM( "symbol->string", symbol_to_string )
    REQ_SYMBOL_ARG( symbol );
    NO_REST_ARGS( );
    RESULT( wasp_vf_string( symbol->string ) );
WASP_END_PRIM( symbol_to_string );

WASP_BEGIN_PRIM( "make-vector", make_vector )
    REQ_INTEGER_ARG( length );
    OPT_ANY_ARG( init );
    NO_REST_ARGS( );
    
    if( length < 0 )wasp_errf( wasp_es_vm, "si", "expected non-negative",
                                length );

    wasp_vector vect = wasp_make_vector( length );

    if( has_init ){
        while( length-- ){
            wasp_vector_put( vect, length, init );
        }
    }
    RESULT( wasp_vf_vector( vect ) );
WASP_END_PRIM( make_vector )

WASP_BEGIN_PRIM( "list-index", list_index )
    REQ_ANY_ARG( item );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    wasp_integer ix = 0;

    while( list ){
        if( wasp_eq( wasp_car( list ), item ) ){
            RESULT( wasp_vf_integer( ix ) );
        }
        ix++;
        wasp_value v = wasp_cdr( list );
        if(!  wasp_is_pair( v ) ){
            NO_RESULT();
        };
        list = wasp_list_fv( v );
    }
    NO_RESULT();
WASP_END_PRIM( list_index );

WASP_BEGIN_PRIM( "memq", memq )
    REQ_ANY_ARG( item );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    while( list ){
        if( wasp_eq( item, wasp_car( list ) ) ){
            RESULT( wasp_vf_pair( list ) );
        }
        list = wasp_list_fv( wasp_cdr( list ) );
    }
    RESULT( wasp_vf_false() );
WASP_END_PRIM( memq );

WASP_BEGIN_PRIM( "member", member )
    REQ_ANY_ARG( item );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    while( list ){
        if( ! wasp_cmp_eq( item, wasp_car( list ) ) ){
            RESULT( wasp_vf_pair( list ) );
        }
        list = wasp_list_fv( wasp_cdr( list ) );
    }
    RESULT( wasp_vf_false() );
WASP_END_PRIM( member );

WASP_BEGIN_PRIM( "exit", exit )
    OPT_INTEGER_ARG( code );
    NO_REST_ARGS( );
    exit( has_code ? code : 0 );
WASP_END_PRIM( exit )

WASP_BEGIN_PRIM( "equal?", equal )
    REQ_ANY_ARG( v0 );
    for(;;){
        OPT_ANY_ARG( vN );
        if( ! has_vN )break;
        if( ! wasp_eqv( v0, vN ) ){
            RESULT( wasp_vf_false( ) );
        }
    }
    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( equal )

WASP_BEGIN_PRIM( "eq?", eq )
    REQ_ANY_ARG( v0 );
    for(;;){
        OPT_ANY_ARG( vN );
        if( ! has_vN )break;
        if( ! wasp_eq( v0, vN ) ){
            RESULT( wasp_vf_false( ) );
        }
    }
    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( eq )

WASP_BEGIN_PRIM( "list?", listq )
    REQ_ANY_ARG( v );
    NO_REST_ARGS( );
    BOOLEAN_RESULT( wasp_is_list( v ) );
WASP_END_PRIM( listq )

WASP_BEGIN_PRIM( "integer?", integerq )
    REQ_ANY_ARG( v );
    NO_REST_ARGS( );
    RESULT( wasp_vf_boolean( ( wasp_is_integer( v ) ) ) );
WASP_END_PRIM( integerq )

WASP_BEGIN_PRIM( "cons", cons )
    REQ_ANY_ARG( car );
    REQ_ANY_ARG( cdr );
    NO_REST_ARGS( );
    RESULT( wasp_vf_pair( wasp_cons( car, cdr ) ) );
WASP_END_PRIM( cons )

WASP_BEGIN_PRIM( "car", car )
    REQ_PAIR_ARG( p );
    NO_REST_ARGS( );
    RESULT( wasp_car( p ) );
WASP_END_PRIM( car )

WASP_BEGIN_PRIM( "cdr", cdr )
    REQ_PAIR_ARG( p );
    NO_REST_ARGS( );
    RESULT( wasp_cdr( p ) );
WASP_END_PRIM( cdr )

WASP_BEGIN_PRIM( "set-car!", set_car )
    REQ_PAIR_ARG( p );
    REQ_ANY_ARG( car );
    NO_REST_ARGS( );
    wasp_set_car( p, car );
    NO_RESULT( );
WASP_END_PRIM( set_car )

WASP_BEGIN_PRIM( "set-cdr!", set_cdr )
    REQ_PAIR_ARG( p );
    REQ_ANY_ARG( cdr );
    NO_REST_ARGS( );
    wasp_set_cdr( p, cdr );
    NO_RESULT( );
WASP_END_PRIM( set_cdr )

WASP_BEGIN_PRIM( "vector", vector )
    wasp_vector vt = wasp_make_vector( wasp_arg_ct - 1 );
    wasp_integer ix = 0;
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item ) break;
        wasp_vector_put( vt, ix, item );
        ix ++;
    }
    RESULT( wasp_vf_vector( vt ) );
WASP_END_PRIM( vector )

WASP_BEGIN_PRIM( "vector-ref", vector_ref )
    REQ_VECTOR_ARG( vector );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );
    if( index < wasp_vector_length( vector ) ){
        RESULT( wasp_vector_get( vector, index ) );
    }else{
        wasp_errf( 
            wasp_es_vm,
            "si", "index exceeds vector length", wasp_vector_length( vector ) 
        );
        NO_RESULT( );
    }
WASP_END_PRIM( vector_ref )

WASP_BEGIN_PRIM( "vector-set!", vector_set )
    REQ_VECTOR_ARG( vector );
    REQ_INTEGER_ARG( index );
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    if( index < wasp_vector_length( vector ) ){
        wasp_vector_put( vector, index, value );
    }else{
        wasp_errf( 
            wasp_es_vm,
            "si", "index exceeds vector length", 
            wasp_vector_length( vector ) 
        );
    };
    NO_RESULT( );
WASP_END_PRIM( vector_set )

WASP_BEGIN_PRIM( "vector-length", vector_length )
    REQ_VECTOR_ARG( vector );
    NO_REST_ARGS( );
    RESULT( wasp_vf_integer( wasp_vector_length( vector ) ) );
WASP_END_PRIM( vector_length )

WASP_BEGIN_PRIM( "string-length", string_length )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );
    RESULT( wasp_vf_integer( wasp_string_length( string ) ) );
WASP_END_PRIM( string_length )

WASP_BEGIN_PRIM( "substring", substring )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( index );
    REQ_INTEGER_ARG( length );
    NO_REST_ARGS( );

    const char* data = wasp_sf_string( string );
    wasp_integer datalen = wasp_string_length( string );
    
    if( index < 0 ) wasp_errf( wasp_es_vm, "s", "index must not be negative" );
    if( index > datalen ) wasp_errf( wasp_es_vm, "s", 
                                    "index must be not exceed the string"
                                    " length" );
    if( length < 0 ) wasp_errf( wasp_es_vm, "s", 
                               "length must not be negative" );
    if( length > datalen ) wasp_errf( wasp_es_vm, "s", 
                                    "length must be not exceed the string"
                                    " length" );
    if( (length + index) > datalen ){
        wasp_errf( wasp_es_vm, "s", 
                  "the sum of index and length must not exceed the"
                  " string length" 
        );
    }

    RESULT( wasp_vf_string( wasp_string_fm( data + index, length ) ) );
WASP_END_PRIM( substring )

WASP_BEGIN_PRIM( "string-head", string_head )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( length );
    NO_REST_ARGS( );

    const char* data = wasp_sf_string( string );
    wasp_integer datalen = wasp_string_length( string );
    
    if( length < 0 ) wasp_errf( wasp_es_vm, "s", 
                               "length must not be negative" );
    if( length > datalen ) length = datalen;
    RESULT( wasp_vf_string( wasp_string_fm( data, length ) ) );
WASP_END_PRIM( string_head )

WASP_BEGIN_PRIM( "string-tail", string_tail )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );

    const char* data = wasp_sf_string( string );
    wasp_integer datalen = wasp_string_length( string );
    wasp_integer length = datalen - index;

    if( index < 0 ) wasp_errf( wasp_es_vm, "s", 
                               "index must not be negative" );
    if( length > datalen ) length = datalen;
    RESULT( wasp_vf_string( wasp_string_fm( data + index, length ) ) );
WASP_END_PRIM( string_tail )

WASP_BEGIN_PRIM( "string-ref", string_ref )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );
    if( index >= wasp_string_length( string ) ){
        wasp_errf( wasp_es_vm, "si", "index exceeds string length", 
                               index );
    }
    RESULT( wasp_vf_integer( wasp_sf_string( string )[index] ) );
WASP_END_PRIM( string_ref )

WASP_BEGIN_PRIM( "=", m_eq )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 == vN ) ){ RESULT( wasp_vf_false( ) ); };
    };

    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( m_eq )

WASP_BEGIN_PRIM( "<", m_lt )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 < vN ) ){ RESULT( wasp_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( m_lt )

WASP_BEGIN_PRIM( ">", m_gt )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 > vN ) ){ RESULT( wasp_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( m_gt )

WASP_BEGIN_PRIM( "<=", m_lte )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 <= vN ) ){ RESULT( wasp_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( m_lte )

WASP_BEGIN_PRIM( ">=", m_gte )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 >= vN ) ){ RESULT( wasp_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( m_gte )

WASP_BEGIN_PRIM( "!=", m_ne )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 != vN ) ){ RESULT( wasp_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( wasp_vf_true( ) );
WASP_END_PRIM( m_ne )

WASP_BEGIN_PRIM( "string=?", string_eqq )
    REQ_STRING_ARG( s0 );
    
    for(;;){
        OPT_STRING_ARG( sN );
        if( ! has_sN )break;
        if( wasp_string_compare( s0, sN ) ){ RESULT( wasp_vf_false( ) ); };
    };

    RESULT( wasp_vf_true( ) );
    NO_REST_ARGS( );
WASP_END_PRIM( string_eqq )

WASP_BEGIN_PRIM( "length", length )
    REQ_LIST_ARG( pair );
    NO_REST_ARGS( );
    INTEGER_RESULT( wasp_list_length( pair ) );
WASP_END_PRIM( length )

WASP_BEGIN_PRIM( "error-key", error_key )
    REQ_ERROR_ARG( err );
    NO_REST_ARGS( );
  
    RESULT( wasp_vf_symbol( err->key ) );
WASP_END_PRIM( error_key )

WASP_BEGIN_PRIM( "error-info", error_info )
    REQ_ERROR_ARG( err );
    NO_REST_ARGS( );
  
    RESULT( wasp_vf_pair( err->info ) );
WASP_END_PRIM( error_info )

WASP_BEGIN_PRIM( "error-context", error_context )
    REQ_ERROR_ARG( err );
    NO_REST_ARGS( );
  
    RESULT( wasp_vf_list( err->context ) );
WASP_END_PRIM( error_context )

WASP_BEGIN_PRIM( "map-car", map_car )
    REQ_LIST_ARG( src );
    NO_REST_ARGS( );
    wasp_tc tc = wasp_make_tc();
    while( src ){
        wasp_pair p = wasp_req_pair( wasp_car( src ) );
        wasp_tc_add( tc, wasp_car( p ) );
        src = wasp_req_list( wasp_cdr( src ) );
    }
    LIST_RESULT( tc->head );
WASP_END_PRIM( map_car );

WASP_BEGIN_PRIM( "map-cdr", map_cdr )
    REQ_LIST_ARG( src );
    NO_REST_ARGS( );
    wasp_tc tc = wasp_make_tc();
    while( src ){
        wasp_pair p = wasp_req_pair( wasp_car( src ) );
        wasp_tc_add( tc, wasp_cdr( p ) );
        src = wasp_req_list( wasp_cdr( src ) );
    }
    LIST_RESULT( tc->head );
WASP_END_PRIM( map_cdr );

WASP_BEGIN_PRIM( "thaw", thaw )
    REQ_STRING_ARG( src );
    NO_REST_ARGS( );
    RESULT( wasp_thaw_str( src ) );
WASP_END_PRIM( thaw );

WASP_BEGIN_PRIM( "freeze", freeze )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    STRING_RESULT( wasp_freeze( value ) );
WASP_END_PRIM( freeze );

WASP_BEGIN_PRIM( "string-append", string_append )
    wasp_string s0 = wasp_make_string( 128 );
    for(;;){
        OPT_ANY_ARG( sN );
        if(! has_sN ) break;
        if( wasp_is_string( sN ) ){
            wasp_string s = wasp_string_fv( sN );
            wasp_string_append( s0, wasp_sf_string( s ), wasp_string_length( s ) );
        }else if( wasp_is_integer( sN ) ){
            wasp_string_append_byte( s0, wasp_integer_fv( sN ) );
        }else{
            wasp_errf( wasp_es_vm, "sx", "expected string or byte", sN );
        }
    }
    STRING_RESULT( s0 );
WASP_END_PRIM( string_append );

WASP_BEGIN_PRIM( "assq", assq )
    REQ_ANY_ARG( key );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    
    wasp_value v;
    if( list ){
        for(;;){
            v = wasp_car( list );
            if( wasp_is_pair( v ) ){
                //TODO: Should this be an error?
                if( wasp_eqv( wasp_car( wasp_pair_fv( v ) ), key ) ){
                    RESULT( v );
                }
            }

            //TODO: Should this be an error?
            v = wasp_cdr( list );
            if( ! wasp_is_pair( v ) )break;
            list = wasp_list_fv( v );
        }
    }

    RESULT( wasp_vf_false() );
WASP_END_PRIM( assq );

WASP_BEGIN_PRIM( "assoc", assoc )
    REQ_ANY_ARG( key );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    
    wasp_value v;
    if( list ){
        for(;;){
            v = wasp_car( list );
            if( wasp_is_pair( v ) ){
                //TODO: Should this be an error?
                if( wasp_eq( wasp_car( wasp_pair_fv( v ) ), key ) ){
                    RESULT( v );
                }
            }
            //TODO: Should this be an error?
            v = wasp_cdr( list  );
            if( ! wasp_is_pair( v ) )break;
            list = wasp_list_fv( v );
        }
    }

    RESULT( wasp_vf_false() );
WASP_END_PRIM( assoc );

WASP_BEGIN_PRIM( "getcwd", getcwd )
    NO_REST_ARGS( );
    static char buf[ MAXPATHLEN ];
    if( getcwd( buf, MAXPATHLEN ) ){
        RESULT( wasp_vf_string( wasp_string_fs( buf ) ) );
    }else{
        wasp_errf( wasp_es_vm, "s", strerror( errno ) );
        NO_RESULT( );
    };
WASP_END_PRIM( getcwd )

WASP_BEGIN_PRIM( "chdir", chdir )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );
    
    wasp_os_error( chdir( wasp_sf_string( path ) ) );
    NO_RESULT( );
WASP_END_PRIM( chdir )

WASP_BEGIN_PRIM( "argv", argv )
    OPT_INTEGER_ARG( ix );
    NO_REST_ARGS( );
    if( has_ix ){
        if( ix < wasp_argc ){
            RESULT( wasp_car( wasp_list_ref( wasp_argv, ix ) ) );
        }else{
            RESULT( wasp_vf_false( ) );
        }
    }else{
        RESULT( wasp_vf_pair( wasp_argv ) );
    };
WASP_END_PRIM( argv )

WASP_BEGIN_PRIM( "argc", argc )
    NO_REST_ARGS( );
    RESULT( wasp_vf_integer( wasp_argc ) );
WASP_END_PRIM( argc )

WASP_BEGIN_PRIM( "refuse-method", refuse_method )
    wasp_errf( wasp_es_vm, "s", "method not found");
WASP_END_PRIM( refuse_method )

WASP_BEGIN_PRIM( "get-global", get_global )
    REQ_SYMBOL_ARG( symbol );
    OPT_ANY_ARG( def );
    NO_REST_ARGS( );

    if( wasp_has_global( symbol ) ){
        RESULT( wasp_get_global( symbol ) );
    }else if( has_def ){
        RESULT( def );
    }else{
        RESULT( wasp_vf_false() );
    }
WASP_END_PRIM( get_global )

WASP_BEGIN_PRIM( "enable-trace", enable_trace )
    NO_REST_ARGS( );
    if( WASP_T < 1000 )WASP_T += 1;
    NO_RESULT();
WASP_END_PRIM( enable_trace )

WASP_BEGIN_PRIM( "disable-trace", disable_trace )
    NO_REST_ARGS( );
    if( WASP_T )WASP_T -= 1;
    NO_RESULT();
WASP_END_PRIM( disable_trace )

WASP_BEGIN_PRIM( "make-tc", make_tc )
    REST_ARGS( seed );

    wasp_tc tc = wasp_make_tc( );

    if( seed ){
        tc->head = seed;
        tc->tail = wasp_last_pair( seed );
    };

    TC_RESULT( tc );
WASP_END_PRIM( make_tc )

WASP_BEGIN_PRIM( "tc-clear!", tc_clear )
    REQ_TC_ARG( tc );
    NO_REST_ARGS( );
    tc->head = tc->tail = (wasp_pair) NULL;
    TC_RESULT( tc );
WASP_END_PRIM( tc_clear )

WASP_BEGIN_PRIM( "tc-append!", tc_append )
    REQ_TC_ARG( tc );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );

    while( list ){
        wasp_tc_add( tc, wasp_car( list ) );
        list = wasp_req_list( wasp_cdr( list ) );
    }

    RESULT( wasp_vf_tc( tc ) );
WASP_END_PRIM( tc_append )

WASP_BEGIN_PRIM( "tc-next!", tc_next )
    REQ_TC_ARG( tc );
    NO_REST_ARGS( );
    if( ! tc->head ){
        wasp_errf( wasp_es_vm, "s", "tconc out of items" );
    }
    wasp_pair next = tc->head;
    wasp_pair lead = wasp_list_fv( wasp_cdr( next ) );
    if( lead ){
        tc->head = lead;
    }else{
        tc->head = tc->tail = (wasp_pair) NULL;
    }
    RESULT( wasp_car( next ) );
WASP_END_PRIM( tc_next );

WASP_BEGIN_PRIM( "tc-empty?", tc_emptyq )
    REQ_TC_ARG( tc );
    NO_REST_ARGS( );
    RESULT( wasp_vf_boolean( tc->head == NULL ) );
WASP_END_PRIM( tc_emptyq );

WASP_BEGIN_PRIM( "tc-add!", tc_add )
    REQ_TC_ARG( tc );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item ) break;
        wasp_tc_add( tc, item );
    }

    RESULT( wasp_vf_tc( tc ) );
WASP_END_PRIM( tc_add )

WASP_BEGIN_PRIM( "tc-remove!", tc_remove )
    REQ_TC_ARG( tc );

    for(;;){
    OPT_ANY_ARG( item );
    if( ! has_item ) break;

        wasp_list prev = NULL;
        wasp_list list = tc->head;

        while( list ){
            if( wasp_eq( wasp_car( list ), item ) ){
                wasp_list next = wasp_list_fv( wasp_cdr( list ) );

                if( prev == NULL ){
                    tc->head = next;
                }else{
                    wasp_set_cdr( prev, wasp_vf_list( next ) );
                };

                if( ! next ){ tc->tail = prev; };
            };

            prev = list;
            list = wasp_list_fv( wasp_cdr( list ) );
        }
    }

    NO_RESULT( );
WASP_END_PRIM( tc_remove )

WASP_BEGIN_PRIM( "tc-prepend!", tc_prepend )
    REQ_TC_ARG( tc );
    REQ_ANY_ARG( item );
    NO_REST_ARGS( );
    wasp_pair pair = wasp_cons( item, wasp_vf_pair( tc->head ) );

    if( ! tc->head ){
        tc->tail = pair;
    };
    tc->head = pair;

    RESULT( wasp_vf_tc( tc ) );
WASP_END_PRIM( tc_prepend )

WASP_BEGIN_PRIM( "tc->list", tc_to_list )
    REQ_TC_ARG( tc );
    NO_REST_ARGS( );
    LIST_RESULT( tc->head );
WASP_END_PRIM( tc_to_list )

wasp_symbol wasp_es_parse;
wasp_symbol wasp_es_inc;

WASP_BEGIN_PRIM( "string->exprs", string_to_exprs )
    REQ_STRING_ARG( src );
    NO_REST_ARGS( );
    
    wasp_boolean ok = 0;
    wasp_list v = wasp_parse_document( wasp_sf_string( src ), &ok );
    if( ok ){
        RESULT( wasp_vf_list( v ) );
    }else{
        wasp_errf( 
            wasp_parse_incomplete ? wasp_es_inc : wasp_es_parse, 
            "s", wasp_parse_errmsg 
        );
    }
WASP_END_PRIM( string_to_exprs )

WASP_BEGIN_PRIM( "globals", globals )
    NO_REST_ARGS( );
    RESULT( wasp_vf_list( wasp_get_globals( ) ) );
WASP_END_PRIM( globals );

WASP_BEGIN_PRIM( "make-set", make_set )
    wasp_set set = wasp_make_set( );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item )break;
        wasp_tree_insert( set, item );
    }
    
    RESULT( wasp_vf_set( set ) );
WASP_END_PRIM( make_set )

WASP_BEGIN_PRIM( "set-add!", set_add )
    REQ_SET_ARG( set );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item )break;
        wasp_tree_insert( set, item );
    }
    
    RESULT( wasp_vf_set( set ) );
WASP_END_PRIM( set_add )

WASP_BEGIN_PRIM( "set-remove!", set_removed )
    REQ_SET_ARG( set );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item )break;
        wasp_tree_remove( set, item );
    }
    
    RESULT( wasp_vf_set( set ) );
WASP_END_PRIM( set_removed )

WASP_BEGIN_PRIM( "set-member?", set_memberq )
    REQ_SET_ARG( set );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item )break;
        if( ! wasp_tree_lookup( set, item ) ) FALSE_RESULT( );
    }
    
    TRUE_RESULT( );
WASP_END_PRIM( set_memberq )

WASP_BEGIN_PRIM( "set->list", set_to_list )
    REQ_SET_ARG( set );
    NO_REST_ARGS( );

    wasp_tc tc = wasp_make_tc( );
    
    wasp_iter_tree( set, (wasp_iter_mt)wasp_untree_cb, tc );

    LIST_RESULT( tc->head  );
WASP_END_PRIM( set_to_list )

WASP_BEGIN_PRIM( "make-dict", make_dict )
    wasp_dict dict = wasp_make_dict( );

    for(;;){
        OPT_PAIR_ARG( entry );
        if( ! has_entry )break;
        wasp_tree_insert( dict, wasp_vf_pair( entry ) );
    }
    
    RESULT( wasp_vf_dict( dict ) );
WASP_END_PRIM( make_dict )

WASP_BEGIN_PRIM( "dict->list", dict_to_list )
    REQ_DICT_ARG( dict );
    NO_REST_ARGS( );

    wasp_tc tc = wasp_make_tc( );
    wasp_iter_tree( dict, (wasp_iter_mt)wasp_untree_cb, tc );
    
    LIST_RESULT( tc->head );
WASP_END_PRIM( dict_to_list )

void wasp_dict_keys_cb( wasp_value value, wasp_tc tc ){
    wasp_pair p = wasp_pair_fv( value );
    wasp_tc_add( tc, wasp_car( p ) );
}

WASP_BEGIN_PRIM( "dict-keys", dict_keys )
    REQ_DICT_ARG( dict );
    NO_REST_ARGS( );

    wasp_tc tc = wasp_make_tc( );

    wasp_iter_tree( dict, (wasp_iter_mt)wasp_dict_keys_cb, tc );
    
    LIST_RESULT( tc->head );
WASP_END_PRIM( dict_keys )

void wasp_dict_values_cb( wasp_value value, wasp_tc tc ){
    wasp_pair p = wasp_pair_fv( value );
    wasp_tc_add( tc, wasp_cdr( p ) );
}

WASP_BEGIN_PRIM( "dict-values", dict_values )
    REQ_DICT_ARG( dict );
    NO_REST_ARGS( );

    wasp_tc tc = wasp_make_tc( );
    
    wasp_iter_tree( dict, (wasp_iter_mt)wasp_dict_values_cb, tc );
    
    LIST_RESULT( tc->head );
WASP_END_PRIM( dict_values )

WASP_BEGIN_PRIM( "dict-set?", dict_setq )
    REQ_DICT_ARG( dict );
    REQ_ANY_ARG( key );
    NO_REST_ARGS( );
    
    RESULT( wasp_tree_lookup( dict, key ) ? wasp_vf_true() : wasp_vf_false() );    
WASP_END_PRIM( dict_setq )

WASP_BEGIN_PRIM( "dict-set!", dict_setd )
    REQ_DICT_ARG( dict );
    REQ_ANY_ARG( key );
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    wasp_tree_insert( dict, wasp_vf_pair( wasp_cons( key, value ) ) );

    NO_RESULT();
WASP_END_PRIM( dict_setd )

WASP_BEGIN_PRIM( "dict-ref", dict_ref )
    REQ_DICT_ARG( dict );
    REQ_ANY_ARG( key );
    OPT_ANY_ARG( alternate );
    NO_REST_ARGS( );
   
    wasp_node node = wasp_tree_lookup( dict, key );
    
    if( node ){
        RESULT( wasp_cdr( wasp_pair_fv( node->data ) ) );
    }else if( has_alternate ){
        RESULT( alternate );
    }else{
        RESULT( wasp_vf_false() );
    }
WASP_END_PRIM( dict_ref )

WASP_BEGIN_PRIM( "dict-remove!", dict_removed )
    REQ_DICT_ARG( dict );
    REQ_ANY_ARG( item );
    NO_REST_ARGS( );
    
    wasp_tree_remove( dict, item );
    
    NO_RESULT( );
WASP_END_PRIM( dict_removed )

char* wasp_memmem( const char* sp, wasp_integer sl, const char* ip, wasp_integer il ){
    wasp_integer i;

    // Like strstr, but \0-ignorant.
    if( sl < il )return NULL;

    sl = sl - il + 1;

    for( i = 0; i < sl; i ++ ){
        if( ! memcmp( sp, ip, il ) ) return (char*)sp;
        sp++;
    }

    return NULL;
}

WASP_BEGIN_PRIM( "string-find", string_find )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    const char* sp = wasp_sf_string( string );
    const char* ip = wasp_memmem( sp, 
                                 wasp_string_length( string ), 
                                 wasp_sf_string( item ), 
                                 wasp_string_length( item ) );
    
    if( ip ){
        RESULT( wasp_vf_integer( ip - sp ) );
    }else{
        RESULT( wasp_vf_false( ) );
    }
WASP_END_PRIM( string_find )

WASP_BEGIN_PRIM( "string-begins-with?", string_begins_with )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    wasp_integer sl = wasp_string_length( string );
    wasp_integer il = wasp_string_length( item );

    if( sl < il ){
        RESULT( wasp_vf_false( ) );
    }else{
        const char* sp = wasp_sf_string( string );
        const char* ip = wasp_sf_string( item );

        RESULT( wasp_vf_boolean( ! memcmp( sp, ip, il ) ) );
    }
WASP_END_PRIM( string_begins_with )

WASP_BEGIN_PRIM( "strip", strip)
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    wasp_integer i, j, sl = wasp_string_length( string );
    const char* sp = wasp_sf_string( string );
    
    for( i = 0; i < sl; i ++ ){
        if( ! isspace( sp[i] ) ) break;
    }
    
    sp += i;
    sl -= i;

    while( sl ){
        if( ! isspace( sp[ sl - 1 ] ) )break;
        sl --;
    }
    
    RESULT( wasp_vf_string( wasp_string_fm( sp, sl ) ) );
WASP_END_PRIM( strip )

WASP_BEGIN_PRIM( "strip-head", strip_head )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    wasp_integer i, sl = wasp_string_length( string );
    const char* sp = wasp_sf_string( string );
    
    for( i = 0; i < sl; i ++ ){
        if( ! isspace( sp[i] ) ) break;
    }

    RESULT( wasp_vf_string(
        i ? wasp_string_fm( sp + i, sl - i ) : string
    ) );
WASP_END_PRIM( strip_head )

WASP_BEGIN_PRIM( "strip-tail", strip_tail )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    wasp_integer sl = wasp_string_length( string );
    const char* sp = wasp_sf_string( string );
  
    while( sl ){
        if( ! isspace( sp[ sl - 1 ] ) )break;
        sl --;
    }
    
    RESULT( wasp_vf_string( wasp_string_fm( sp, sl ) ) );
WASP_END_PRIM( strip_tail )

WASP_BEGIN_PRIM( "string-ends-with?", string_ends_with )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    wasp_integer sl = wasp_string_length( string );
    wasp_integer il = wasp_string_length( item );

    if( sl < il ){
        RESULT( wasp_vf_false( ) );
    }else{
        const char* sp = wasp_sf_string( string ) + sl - il;
        const char* ip = wasp_sf_string( item );

        RESULT( wasp_vf_boolean( ! memcmp( sp, ip, il ) ) );
    }
WASP_END_PRIM( string_ends_with )

WASP_BEGIN_PRIM( "split-lines", split_lines )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );
    
    const char* sp = wasp_sf_string( string );
    const char* bp = sp;
    wasp_tc tc = wasp_make_tc( tc );
    char ch;

    void add_item( ){
        wasp_tc_add( tc, wasp_vf_string( wasp_string_fm( bp, sp - bp ) ) );
    }

    while( ch = *sp ){
        switch( ch ){
        case '\r':
            add_item( );
            if( sp[1] == '\n' ) sp++;
            bp = sp + 1;
            break;
        case '\n':
            add_item( );
            bp = sp + 1;
            break;
        };
        sp ++;
    };

    add_item( );
    
    LIST_RESULT( tc->head );
WASP_END_PRIM( split_lines )

WASP_BEGIN_PRIM( "string-split", string_split )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    const char* sp = wasp_sf_string( string );
    wasp_integer sl = wasp_string_length( string );
    const char* ip = wasp_sf_string( item );
    wasp_integer il = wasp_string_length( item );
    const char* pp = wasp_memmem( sp, sl, ip, il );
    
    if( pp ){
        wasp_integer pl = pp - sp;
        item = wasp_string_fm( sp, pl );
        string = wasp_string_fm( pp + il, sl - il - pl );
        RESULT( 
                wasp_vf_pair( wasp_cons( wasp_vf_string( item ),
                             wasp_vf_pair( 
                                 wasp_cons( wasp_vf_string( string ),
                                           wasp_vf_null( ) ) ) ) ) );
    }else{
        RESULT( wasp_vf_pair( wasp_cons( wasp_vf_string( string ),
                                           wasp_vf_null( ) ) ) );
    }
WASP_END_PRIM( string_split )

WASP_BEGIN_PRIM( "string-replace", string_replace )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( pattern );
    REQ_STRING_ARG( replacement );
    NO_REST_ARGS( );
    
    const char* sp = wasp_sf_string( string );
    wasp_integer sl = wasp_string_length( string );

    const char* ip = wasp_sf_string( pattern );
    wasp_integer il = wasp_string_length( pattern );
    
    const char* rp = wasp_sf_string( replacement );
    wasp_integer rl = wasp_string_length( replacement );
    
    wasp_tc tc = wasp_make_tc( );
    const char* pp;
 
    wasp_string buf = wasp_make_string( sl );
    while( pp = wasp_memmem( sp, sl, ip, il ) ){
        wasp_integer pl = pp - sp;
        wasp_string_append( buf, sp, pl );
        wasp_string_append( buf, rp, rl );
        sl = sl - pl - il;
        sp = sp + pl + il;
    }
   
    wasp_string_append( buf, sp, sl );
    
    STRING_RESULT( buf );
WASP_END_PRIM( string_replace )

WASP_BEGIN_PRIM( "string-split*", string_splitm )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    const char* sp = wasp_sf_string( string );
    wasp_integer sl = wasp_string_length( string );

    const char* ip = wasp_sf_string( item );
    wasp_integer il = wasp_string_length( item );
    
    wasp_tc tc = wasp_make_tc( );
    const char* pp;
  
    while( pp = wasp_memmem( sp, sl, ip, il ) ){
        wasp_integer pl = pp - sp;
        item = wasp_string_fm( sp, pl );
        wasp_tc_add( tc, wasp_vf_string( item ) );    
        sl = sl - pl - il;
        sp = sp + pl + il;
    }
    
    wasp_tc_add( tc, wasp_vf_string( wasp_string_fm( sp, sl ) ) );

    LIST_RESULT( tc->head );
WASP_END_PRIM( string_splitm )

WASP_BEGIN_PRIM( "string-join", string_join )
    // Most languages use join( list, sep ), but in Lisp, it's always nice
    // to ensure that the list argument is last, to permit the use and
    // abuse of Apply, e.g.
    //
    // (apply string-join ", " items)
    
    REQ_STRING_ARG( sep );

    wasp_string res = wasp_make_string( 128 );
    int any = 0;

    for(;;){
        OPT_STRING_ARG( item );
        if( ! has_item ) break;
        if( any ){
            wasp_string_append( res, wasp_sf_string( sep ), 
                                    wasp_string_length( sep ) );
        }
        any = 1;
        wasp_string_append( res, wasp_sf_string( item ), 
                                wasp_string_length( item ) );
    }
    
    RESULT( wasp_vf_string( res ) );
WASP_END_PRIM( string_join )

WASP_BEGIN_PRIM( "function?", functionq )
    REQ_ANY_ARG( value )
    NO_REST_ARGS( );

    BOOLEAN_RESULT( wasp_is_function( value ) );
WASP_END_PRIM( functionq )

WASP_BEGIN_PRIM( "function-name", function_name )
    REQ_ANY_ARG( function )
    NO_REST_ARGS( );

    RESULT( wasp_function_name( function ) );
WASP_END_PRIM( function_name )

WASP_BEGIN_PRIM( "make-string", make_string )
    OPT_INTEGER_ARG( capacity );
    NO_REST_ARGS( );
    
    if( ! has_capacity ){ 
        capacity = 1024; 
    }else if( capacity < 0 ){
        wasp_errf( wasp_es_vm, "sx", "expected non-negative", capacity );
    }

    wasp_string string = wasp_make_string( capacity );

    RESULT( wasp_vf_string( string ) );
WASP_END_PRIM( make_string )

WASP_BEGIN_PRIM( "flush-string", flush_string )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    wasp_string_flush( string );
    NO_RESULT( );
WASP_END_PRIM( flush_string )

WASP_BEGIN_PRIM( "empty-string?", empty_stringq )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );

    RESULT( wasp_vf_boolean( wasp_string_empty( string ) ) );
WASP_END_PRIM( string_empty )

WASP_BEGIN_PRIM( "string-skip-space!", string_skip_space )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );
    
    wasp_quad ix, len = wasp_string_length( string );
    const char* str = wasp_sf_string( string );
   
    for( ix = 0; ix < len; ix ++ ){
        if( ! isspace( str[ix] ) )break;
    }
    
    if( ix )wasp_string_skip( string, ix );
    
    INTEGER_RESULT( ix );
WASP_END_PRIM( string_skip_space );

WASP_BEGIN_PRIM( "string-skip!", string_skip )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );
    if( offset > wasp_string_length( string ) ){
        wasp_errf( wasp_es_vm, "s", "skip past end of string" );
    }
    wasp_string_skip( string, offset );
    NO_RESULT( );
WASP_END_PRIM( string_skip );

WASP_BEGIN_PRIM( "string-read!", string_read )
    REQ_STRING_ARG( string );
    OPT_INTEGER_ARG( max );
    NO_REST_ARGS( );
    if( ! has_max ) max = wasp_string_length( string );
    void* data = wasp_string_read( string, &max );
    RESULT( wasp_vf_string( wasp_string_fm( data, max ) ) );
WASP_END_PRIM( string_read );

WASP_BEGIN_PRIM( "string-append-byte!", string_append_byte )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( byte )
    NO_REST_ARGS( );
    
    if(!( 0<= byte <= 255 )){
        wasp_errf( wasp_es_vm, "sx", "expected data to be in [0,255]",
                  byte );
    }
    wasp_byte data = byte;
    wasp_string_append( string, &data, sizeof( wasp_byte ) );

    NO_RESULT( );
WASP_END_PRIM( string_append_byte )

WASP_BEGIN_PRIM( "string-read-byte!", string_read_byte )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );
    
    wasp_integer read = sizeof( wasp_byte );

    if( wasp_string_length( string ) < read ){
        RESULT( wasp_vf_false( ) );
    }
    
    wasp_byte* data = wasp_string_read( string, &read ); 

    RESULT( wasp_vf_integer( *data ) );
WASP_END_PRIM( string_read_byte )

WASP_BEGIN_PRIM( "string-read-line!", string_read_line )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );
    
    wasp_integer linelen; 
    const char* line = wasp_string_read_line( string, &linelen ); 
    
    RESULT( line ? wasp_vf_string( wasp_string_fm( line, linelen ) ) 
                     : wasp_vf_false( ) );
WASP_END_PRIM( string_read_line )

WASP_BEGIN_PRIM( "string-append-word!", string_append_word )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( word )
    NO_REST_ARGS( );
    
    if(!( 0<= word <= 65535 )){
        wasp_errf( wasp_es_vm, "sx", "expected data to be in [0,65535]",
                  word );
    }
    
    wasp_string_append_word( string, word );

    NO_RESULT( );
WASP_END_PRIM( string_append_word )

WASP_BEGIN_PRIM( "string-read-word!", string_read_word )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );
    
    wasp_integer read = sizeof( wasp_word );

    if( wasp_string_length( string ) < read ){
        RESULT( wasp_vf_false( ) );
    }
    
    wasp_word* data = wasp_string_read( string, &read ); 

    RESULT( wasp_vf_integer( ntohs( *data ) ) );
WASP_END_PRIM( string_read_word )

WASP_BEGIN_PRIM( "string-append-quad!", string_append_quad )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( quad )
    NO_REST_ARGS( );
    
    wasp_string_append_quad( string, quad );

    NO_RESULT( );
WASP_END_PRIM( string_append_quad )

WASP_BEGIN_PRIM( "string-read-quad!", string_read_quad )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );
    
    wasp_integer read = sizeof( wasp_quad );

    if( wasp_string_length( string ) < read ){
        RESULT( wasp_vf_false( ) );
    }
    
    wasp_quad* data = wasp_string_read( string, &read ); 

    RESULT( wasp_vf_integer( ntohl( *data ) ) );
WASP_END_PRIM( string_read_quad )

WASP_BEGIN_PRIM( "string-alter!", string_alterd )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( offset )
    REQ_INTEGER_ARG( length )
    REQ_STRING_ARG( data )
    NO_REST_ARGS( )
    
    if(( offset + length ) > wasp_string_length( string ) ){
        wasp_errf( wasp_es_vm, "s", "replaced portion not within string" );
    }

    wasp_string_alter( string, offset, length, 
                      wasp_sf_string( data ), wasp_string_length( data ) );
    
    NO_RESULT( );
WASP_END_PRIM( string_alterd )

WASP_BEGIN_PRIM( "byte->string", byte_to_string );
    REQ_INTEGER_ARG( byte )
    NO_REST_ARGS( );

    wasp_string str = wasp_make_string( 4 );
    wasp_string_append_byte( str, byte );
    
    STRING_RESULT( str );
WASP_END_PRIM( byte_to_string )

WASP_BEGIN_PRIM( "word->string", word_to_string );
    REQ_INTEGER_ARG( word )
    NO_REST_ARGS( );

    wasp_string str = wasp_make_string( 4 );
    wasp_string_append_word( str, word );
    
    STRING_RESULT( str );
WASP_END_PRIM( word_to_string )

WASP_BEGIN_PRIM( "quad->string", quad_to_string );
    REQ_INTEGER_ARG( quad )
    NO_REST_ARGS( );

    wasp_string str = wasp_make_string( 4 );
    wasp_string_append_quad( str, quad );
    
    STRING_RESULT( str );
WASP_END_PRIM( quad_to_string )

WASP_BEGIN_PRIM( "string-prepend!", string_prependd )
    REQ_STRING_ARG( string )
    REQ_ANY_ARG( data )
    NO_REST_ARGS( )
    
    void* src; wasp_integer srclen;

    if( wasp_is_string( data ) ){
        wasp_string str = wasp_string_fv( data );
        src = wasp_sf_string( str );
        srclen = wasp_string_length( str );
    }else if( wasp_is_integer( data ) ){
        wasp_byte x = wasp_integer_fv( data );
        src = &x;
        srclen = 1;
    }

    wasp_string_prepend( string, src, srclen );
    
    NO_RESULT( );
WASP_END_PRIM( string_prependd )

WASP_BEGIN_PRIM( "append", append )
    wasp_tc tc = wasp_make_tc( );

    for(;;){
        OPT_LIST_ARG( list );
        if( ! has_list )break;
        while( list ){
            wasp_tc_add( tc, wasp_car( list ) );
            list = wasp_req_list( wasp_cdr( list ) );
        }
    }
    
    LIST_RESULT( tc->head );
WASP_END_PRIM( append )

WASP_BEGIN_PRIM( "append!", appendd )
    wasp_value head = 0;
    wasp_value* link = &head;

    for(;;){
        OPT_LIST_ARG( next );
        if( ! has_next )break;
        if( ! next )continue;
        *link = wasp_vf_pair( next );
        link = &( wasp_last_pair( next )->cdr );
    }

    RESULT( head );
WASP_END_PRIM( appendd )

WASP_BEGIN_PRIM( "string-append!", string_appendd )
    REQ_STRING_ARG( string )
    
    void* src; wasp_integer srclen;
   
    for(;;){
        OPT_ANY_ARG( data );
        if( ! has_data ){ 
            break;
        }else if( wasp_is_string( data ) ){
            wasp_string str = wasp_string_fv( data );
            src = wasp_sf_string( str );
            srclen = wasp_string_length( str );
        }else if( wasp_is_integer( data ) ){
            wasp_byte x = wasp_integer_fv( data );
            src = &x;
            srclen = 1;
        }else{
            wasp_errf( wasp_es_vm, "sx", "expected string or character", data );
        }
        wasp_string_append( string, src, srclen );
    }
    
    NO_RESULT( );
WASP_END_PRIM( string_appendd )

WASP_BEGIN_PRIM( "string-erase!", string_erased )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( offset )
    REQ_INTEGER_ARG( length )
    NO_REST_ARGS( )
    
    if(( offset + length ) > wasp_string_length( string ) ){
        wasp_errf( wasp_es_vm, "s", "erased portion not within string" );
    }

    wasp_string_alter( string, offset, length, NULL, 0 );
    
    NO_RESULT( );
WASP_END_PRIM( string_erased )

WASP_BEGIN_PRIM( "string-insert!", string_insertd )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( offset )
    REQ_ANY_ARG( data )
    NO_REST_ARGS( )
    
    void* src; wasp_integer srclen;

    if( wasp_is_string( data ) ){
        wasp_string str = wasp_string_fv( data );
        src = wasp_sf_string( str );
        srclen = wasp_string_length( str );
    }else if( wasp_is_integer( data ) ){
        wasp_byte x = wasp_integer_fv( data );
        src = &x;
        srclen = 1;
    }

    if( offset > wasp_string_length( string ) ){
        wasp_errf( wasp_es_vm, "s", "insertion past end of string" );
    }

    wasp_string_alter( string, offset, 0, src, srclen );
    
    NO_RESULT( );
WASP_END_PRIM( string_insertd )

WASP_BEGIN_PRIM( "copy-string", copy_string )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( )

    wasp_string new = wasp_string_fm( wasp_sf_string( string ),
                                      wasp_string_length( string ) );

    RESULT( wasp_vf_string( new ) );
WASP_END_PRIM( copy_string )

void wasp_bind_core_prims( ){
    wasp_set_global( wasp_symbol_fs( "*platform*" ), 
    wasp_vf_string( wasp_string_fs( WASP_PLATFORM ) ) );

    WASP_BIND_PRIM( integerq );
    WASP_BIND_PRIM( listq );
    WASP_BIND_PRIM( cons );
    WASP_BIND_PRIM( car );
    WASP_BIND_PRIM( cdr );
    WASP_BIND_PRIM( cadr );
    WASP_BIND_PRIM( caddr );
    WASP_BIND_PRIM( set_car );
    WASP_BIND_PRIM( set_cdr );
    WASP_BIND_PRIM( length );
    WASP_BIND_PRIM( make_vector );
    WASP_BIND_PRIM( vector );
    WASP_BIND_PRIM( vector_set );
    WASP_BIND_PRIM( vector_ref );
    WASP_BIND_PRIM( vector_length );
    WASP_BIND_PRIM( eq );
    WASP_BIND_PRIM( equal );
    WASP_BIND_PRIM( memq );
    WASP_BIND_PRIM( member );
    WASP_BIND_PRIM( assoc );
    WASP_BIND_PRIM( assq );
    WASP_BIND_PRIM( string_append );
    WASP_BIND_PRIM( string_length );
    WASP_BIND_PRIM( string_ref );
    WASP_BIND_PRIM( list_index );
    WASP_BIND_PRIM( list_ref );
    WASP_BIND_PRIM( list_refp );
    WASP_BIND_PRIM( m_lt );    
    WASP_BIND_PRIM( m_gt );    
    WASP_BIND_PRIM( m_lte );    
    WASP_BIND_PRIM( m_gte );    
    WASP_BIND_PRIM( m_eq );    
    WASP_BIND_PRIM( m_ne );    
    WASP_BIND_PRIM( m_mul );    
    WASP_BIND_PRIM( m_div );    
    WASP_BIND_PRIM( m_abs );    
    WASP_BIND_PRIM( quotient );    
    WASP_BIND_PRIM( remainder );    
    WASP_BIND_PRIM( string_eqq );    
    WASP_BIND_PRIM( exit );    
    WASP_BIND_PRIM( number_to_string );    
    WASP_BIND_PRIM( string_to_symbol );    
    WASP_BIND_PRIM( symbol_to_string );    
    WASP_BIND_PRIM( last_item );
    WASP_BIND_PRIM( last_pair );
    WASP_BIND_PRIM( not );
    WASP_BIND_PRIM( equalq );    
    WASP_BIND_PRIM( reverse );    
    WASP_BIND_PRIM( reversed );    

    // Extensions to R5RS
    WASP_BIND_PRIM( map_car );
    WASP_BIND_PRIM( map_cdr );

    WASP_BIND_PRIM( thaw );
    WASP_BIND_PRIM( freeze );
    WASP_BIND_PRIM( getcwd );
    WASP_BIND_PRIM( chdir );
    WASP_BIND_PRIM( argv );
    WASP_BIND_PRIM( argc );

    WASP_BIND_PRIM( refuse_method );

    WASP_BIND_PRIM( get_global );
    
    WASP_BIND_PRIM( enable_trace );
    WASP_BIND_PRIM( disable_trace );

    WASP_BIND_PRIM( make_tc );
    WASP_BIND_PRIM( tc_append );
    WASP_BIND_PRIM( tc_add );
    WASP_BIND_PRIM( tc_remove );
    WASP_BIND_PRIM( tc_prepend );
    WASP_BIND_PRIM( tc_to_list );
    WASP_BIND_PRIM( tc_next );
    WASP_BIND_PRIM( tc_emptyq );
    WASP_BIND_PRIM( tc_clear );

    WASP_BIND_PRIM( string_to_exprs );

    WASP_BIND_PRIM( vector_to_list );
    WASP_BIND_PRIM( list_to_vector );

    WASP_BIND_PRIM( make_set );
    WASP_BIND_PRIM( set_add );
    WASP_BIND_PRIM( set_removed );
    WASP_BIND_PRIM( set_memberq );
    WASP_BIND_PRIM( set_to_list );
    
    WASP_BIND_PRIM( make_dict );
    WASP_BIND_PRIM( dict_setd );
    WASP_BIND_PRIM( dict_ref );
    WASP_BIND_PRIM( dict_removed );
    WASP_BIND_PRIM( dict_setq );
    WASP_BIND_PRIM( dict_to_list );
    WASP_BIND_PRIM( dict_keys );
    WASP_BIND_PRIM( dict_values );

    WASP_BIND_PRIM( string_find );
    WASP_BIND_PRIM( string_split );
    WASP_BIND_PRIM( string_splitm );
    WASP_BIND_PRIM( string_join );
    WASP_BIND_PRIM( string_begins_with );
    WASP_BIND_PRIM( string_ends_with );

    WASP_BIND_PRIM( split_lines );
    
    WASP_BIND_PRIM( globals );
    WASP_BIND_PRIM( function_name );
    WASP_BIND_PRIM( functionq );

    WASP_BIND_PRIM( make_string );
    WASP_BIND_PRIM( flush_string );
    WASP_BIND_PRIM( empty_stringq );
    WASP_BIND_PRIM( string_append );
    WASP_BIND_PRIM( string_skip );

    WASP_BIND_PRIM( string_append_byte ); //DEPRECATE
    WASP_BIND_PRIM( string_append_word ); //DEPRECATE
    WASP_BIND_PRIM( string_append_quad ); //DEPRECATE
    WASP_BIND_PRIM( string_read_byte ); //DEPRECATE
    WASP_BIND_PRIM( string_read_word ); //DEPRECATE
    WASP_BIND_PRIM( string_read_quad ); //DEPRECATE

    WASP_BIND_PRIM( string_read ); //DEPRECATE FOR STRING_TAKED
    WASP_BIND_PRIM( string_read_line ); //DEPRECATE FOR STRING_SPLIT_LINED

    WASP_BIND_PRIM( byte_to_string );
    WASP_BIND_PRIM( word_to_string );
    WASP_BIND_PRIM( quad_to_string );

    // WASP_BIND_PRIM( string_to_byte );
    // WASP_BIND_PRIM( string_to_word );
    // WASP_BIND_PRIM( string_to_quad );

    WASP_BIND_PRIM( append );
    WASP_BIND_PRIM( appendd );
    WASP_BIND_PRIM( substring );
    WASP_BIND_PRIM( string_head );
    WASP_BIND_PRIM( string_tail );

    WASP_BIND_PRIM( string_to_integer )
    WASP_BIND_PRIM( string_replace )
    
    WASP_BIND_PRIM( strip_head );
    WASP_BIND_PRIM( strip_tail );
    WASP_BIND_PRIM( strip );
    WASP_BIND_PRIM( string_skip_space );
    
    WASP_BIND_PRIM( string_alterd );
    WASP_BIND_PRIM( string_prependd );
    WASP_BIND_PRIM( string_appendd );
    WASP_BIND_PRIM( string_insertd );
    WASP_BIND_PRIM( string_erased );
    
    WASP_BIND_PRIM( copy_string );
    
    WASP_BIND_PRIM( error_key );
    WASP_BIND_PRIM( error_info );
    WASP_BIND_PRIM( error_context );

    WASP_BIND_PRIM( exprs_to_string );

    WASP_BIND_PRIM( xml_escape );
    WASP_BIND_PRIM( percent_encode );
    WASP_BIND_PRIM( percent_decode );
    
    WASP_BIND_PRIM( string_read_expr );

    wasp_set_global( wasp_symbol_fs( "*version*" ), 
                    wasp_vf_string( wasp_string_fs( WASP_VERSION ) ) );
    wasp_es_parse = wasp_symbol_fs( "parse" );
    wasp_root_obj( (wasp_object) wasp_es_parse );
    wasp_es_inc = wasp_symbol_fs( "inc" );
    wasp_root_obj( (wasp_object) wasp_es_inc );
}
