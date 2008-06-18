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
#include <stdarg.h>

struct wasp_pool_data wasp_pair_scrap_data;
wasp_pool wasp_pair_scrap = &wasp_pair_scrap_data;

wasp_pair wasp_make_pair( ){
    return (wasp_pair) wasp_scavenge( wasp_pair_type, wasp_pair_scrap, sizeof( struct wasp_pair_data ) );
}
wasp_tc wasp_make_tc( ){
    return (wasp_tc) wasp_scavenge( wasp_tc_type, wasp_pair_scrap, sizeof( struct wasp_pair_data ) );
}
wasp_pair wasp_cons( wasp_value car, wasp_value cdr ){
    wasp_pair c = wasp_make_pair( );
    wasp_set_car( c, car );
    wasp_set_cdr( c, cdr );
    return c;    
}
void wasp_tc_add( wasp_tc tc, wasp_value v ){
    wasp_pair it = wasp_cons( v, wasp_vf_null() );
    wasp_pair lt = tc->tail;
    
    if( lt ){
        wasp_set_cdr( lt, wasp_vf_pair( it ) );
    }else{
        tc->head = it;
    }
    
    tc->tail = it;
}
wasp_pair wasp_list_ref( wasp_pair p, wasp_integer offset ){
    while( p && offset ){
        offset--; 
        p = wasp_req_list( wasp_cdr( p ) );
    }
    return p;
}

wasp_integer wasp_list_length( wasp_list p ){
    //TODO: Does not handle circular lists.
    wasp_integer c = 0;
    while( p ){
        c += 1;
        p = wasp_req_list( wasp_cdr( p ) );
    }
done:
    return c;
}
wasp_pair wasp_last_pair( wasp_pair p ){
    //TODO: Does not handle circular lists.
    if( ! p ){ goto done; }
    for(;;){
        wasp_value v = wasp_cdr( p );
        if( ! wasp_is_pair( v ) ){
            goto done;
        }else{
            p = wasp_pair_fv( v );
        };
    }
done:
    return p;
}

void wasp_trace_pair( wasp_pair p ){
    wasp_grey_val( wasp_car( p ) );
    wasp_grey_val( wasp_cdr( p ) );
}

void wasp_trace_tc( wasp_tc p ){
    wasp_grey_obj( (wasp_object) p->head );
    wasp_grey_obj( (wasp_object) p->tail );
}

void wasp_format_list_items( void* bbuf, wasp_pair p, wasp_boolean sp ){
    wasp_string buf = bbuf;
    if( p == NULL )return;
    
    for(;;){
        wasp_value car = wasp_car( p );
        wasp_value cdr = wasp_cdr( p );
    
        if( sp )wasp_string_append_byte( buf, ' ' );
        sp = 1;
        if( ! wasp_format_item( buf, car ) )break;

        if( wasp_is_null( cdr ) ){
            return;
        }else if( wasp_is_pair( cdr ) ){
            p = wasp_pair_fv( cdr );
        }else{
            wasp_string_append_cs( buf, " . " );
            if( ! wasp_format_item( buf, cdr ) )break;
            return;
        }
    }
}
wasp_pair wasp_listf( wasp_integer ct, ... ){
    va_list ap;
    wasp_pair head = NULL;
    wasp_pair tail = NULL;
    wasp_pair item = NULL;

    va_start( ap, ct );
    while( ct -- ){
        wasp_value value = va_arg( ap, wasp_value );
                
        item = wasp_cons( value, wasp_vf_null( ) );

        if( tail ){
            wasp_set_cdr( tail, wasp_vf_pair( item ) );
        }else{
            head = item;
        };
        tail = item;
    }
done:
    va_end( ap );
    return head;
}

void wasp_format_pair( void* bbuf, wasp_pair p ){
    wasp_string buf = bbuf;
    wasp_string_append_byte( buf, '(' );
    if( p ){
        wasp_format_list_items( buf, p, 0 );
    }
    wasp_string_append_byte( buf, ')' );
}

void wasp_free_pair( wasp_pair p ){
    wasp_discard( (wasp_object)p, wasp_pair_scrap );
}
WASP_GENERIC_COMPARE( pair );
WASP_C_TYPE( pair );

WASP_GENERIC_COMPARE( tc );
WASP_GENERIC_FORMAT( tc );
WASP_GENERIC_FREE( tc );

WASP_C_TYPE( tc );

// A very complicated and sophisticated primitive..
WASP_BEGIN_PRIM( "list", list )
    REST_ARGS( items )
    LIST_RESULT( items )
WASP_END_PRIM( list )

void wasp_init_list_subsystem( ){
    WASP_I_TYPE( pair );
    WASP_I_TYPE( tc );
    WASP_BIND_PRIM( list );
}
