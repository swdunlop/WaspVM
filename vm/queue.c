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

void wasp_queue_xmit( wasp_queue_output output, wasp_value data ){
    wasp_queue_input input = ((wasp_queue)output->queue)->input;

    if( wasp_input_monitored( (wasp_input) input ) ){
        wasp_wake_monitor( (wasp_input)input, data );
    }else{  
        wasp_mq_xmit( ((wasp_queue)input->queue)->mq, (void*)data );
    }
}

int wasp_queue_recv( wasp_queue_input input, wasp_value* data ){
    int r = wasp_mq_recv( ((wasp_queue)input->queue)->mq, (void**)data );
    return r;
}

wasp_queue wasp_make_queue( ){
    wasp_queue q = WASP_OBJALLOC( queue );
    q->input = WASP_OBJALLOC( queue_input );
    q->output = WASP_OBJALLOC( queue_output );
    q->mq = wasp_make_mq( WASP_QUEUE_GC );
    q->input->queue = q;
    q->input->input.recv = (wasp_input_mt)wasp_queue_recv;
    q->output->queue = q;
    q->output->output.xmit = (wasp_output_mt)wasp_queue_xmit;
    return q;
}

void wasp_trace_queue( wasp_queue q ){
    wasp_grey_obj( (wasp_object) q->input );
    wasp_grey_obj( (wasp_object) q->output );
    wasp_trace_mq( q->mq, (wasp_gc_mt)wasp_grey_val );
}

void wasp_free_queue( wasp_queue q ){
    //TODO:QUEUELEAK
    wasp_decref_mq( q->mq );
    wasp_objfree( (wasp_object) q );
}

void wasp_trace_queue_input( wasp_queue_input i ){
    wasp_grey_obj( i->queue );
    wasp_trace_input( (wasp_input) i );
}

void wasp_trace_queue_output( wasp_queue_output o ){
    wasp_grey_obj( o->queue );
}

WASP_GENERIC_FORMAT( queue );
WASP_GENERIC_COMPARE( queue );
WASP_C_TYPE( queue );

WASP_GENERIC_FREE( queue_input );
WASP_GENERIC_FORMAT( queue_input );
WASP_GENERIC_COMPARE( queue_input );
WASP_C_TYPE2( queue_input, "queue-input" );

WASP_GENERIC_FREE( queue_output );
WASP_GENERIC_FORMAT( queue_output );
WASP_GENERIC_COMPARE( queue_output );
WASP_C_TYPE2( queue_output, "queue-output" );

WASP_BEGIN_PRIM( "make-queue", make_queue )
    NO_REST_ARGS( );

    RESULT( wasp_vf_queue( wasp_make_queue( ) ) );
WASP_END_PRIM( make_queue )

WASP_BEGIN_PRIM( "queue-input", queue_input )
    REQ_QUEUE_ARG( queue );
    NO_REST_ARGS( );

    RESULT( wasp_vf_queue_input( queue->input ) );
WASP_END_PRIM( queue_input );

WASP_BEGIN_PRIM( "queue-output", queue_output )
    REQ_QUEUE_ARG( queue );
    NO_REST_ARGS( );

    RESULT( wasp_vf_queue_output( queue->output ) );
WASP_END_PRIM( queue_output );

void wasp_init_queue_subsystem( ){
    WASP_I_TYPE( queue );
    WASP_I_SUBTYPE( queue_input, input );
    WASP_I_SUBTYPE( queue_output, output );
    WASP_BIND_PRIM( make_queue );
    WASP_BIND_PRIM( queue_input );
    WASP_BIND_PRIM( queue_output );
}
