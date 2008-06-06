/* Copyright (C) 2006, Scott W. Dunlop <swdunlop@gmail.com>
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

void wasp_mq_heap( void* obj ){ free( obj ); }
void wasp_mq_gc( ){ };

wasp_mq wasp_make_mq( wasp_gc_mt free ){
    wasp_mq q = (wasp_mq)malloc( sizeof( struct wasp_mq_data ) );
    q->first = q->last = NULL;
    q->refct = 1;
    q->free = free;
    return q;
}

void wasp_mq_xmit( wasp_mq q, void* data ){
    wasp_message m = (wasp_message)malloc( sizeof( struct wasp_message_data ) );

    if( q->last ){
        q->last->next = m;
    }else{
        q->first = m;
    };

    m->next = NULL;
    q->last = m;
    m->content = data;
}

int wasp_mq_recv( wasp_mq q, void** data ){
    wasp_message m = q->first;
    wasp_message n;

    if( ! m ){
        return 0;
    };

    n = m->next;

    if( n ){
        q->first = n;
    }else{
        q->first = q->last = NULL;
    }
    
    if( data ) *data = m->content;
    free( m );

    return 1;
}

void wasp_incref_mq( wasp_mq q ){
    q->refct ++;
}

void wasp_decref_mq( wasp_mq q ){
    wasp_message m, n;

    if( ! ( -- q->refct ) ){
        m = q->first;
        while( m ){
            q->free( m->content );
            n = m->next;
            free( m );
            m = n;
        }
    };
}

void wasp_trace_mq( wasp_mq q, wasp_gc_mt trace ){
    wasp_message m, n;

    m = q->first;
    while( m ){
        trace( m->content );
        n = m->next;
        m = n;
    }
}
