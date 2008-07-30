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

wasp_symbol wasp_ss_timeout;

/*

void wasp_get_now( wasp_quad* secs, wasp_quad* nsecs ){
    struct timespec ts;
    clock_gettime( CLOCK_REALTIME, &ts );
    *secs = ts.tv_sec;
    *nsecs = ts.tv_nsec;
}

*/

#ifdef WASP_IN_WIN32
#include <windows.h>
void wasp_get_now( wasp_quad* secs, wasp_quad* nsecs ){
    wasp_quad ms = GetTickCount( );
    *secs = ms / 1000;
    // 1,000,00 nanoseconds per millisecond
    *nsecs = ( ms % 1000 ) * 1000000; 
}
#else
#include <sys/time.h>
void wasp_get_now( wasp_quad* secs, wasp_quad* nsecs ){
    struct timeval ts;
    gettimeofday( &ts, NULL );
    *secs = ts.tv_sec;
    *nsecs = ts.tv_usec * 1000;
}
#endif

void wasp_cancel_timeout( wasp_timeout timeout ){
    evtimer_del( &( timeout->event ) );
    //TODO: How to unroot an atomic bomb?
    wasp_unroot_obj( (wasp_object) timeout );
}

void wasp_timeout_cb( int fd, short evt, void* context ){
    wasp_timeout timeout = (wasp_timeout) context; 

    if( wasp_input_monitored( timeout->input ) ){
        wasp_wake_monitor( timeout->input, wasp_vf_symbol( wasp_ss_timeout ) );
    };

    wasp_cancel_timeout( timeout );
}

wasp_timeout wasp_make_timeout( wasp_quad ms, wasp_input input ){
    wasp_timeout timeout = WASP_OBJALLOC( timeout );
    evtimer_set( &( timeout->event ), wasp_timeout_cb, timeout );
    timeout->input = input;
    return timeout;
}

wasp_timeout wasp_schedule_timeout( wasp_timeout timeout, wasp_quad ms ){
    wasp_root_obj( (wasp_object) timeout );
    gettimeofday( &( timeout->time ), NULL );
    timeout->time.tv_sec = ms / 1000;
    timeout->time.tv_usec = ((ms % 1000)) * 1000;
    evtimer_add( &( timeout->event ), &( timeout->time ) );
}

void wasp_trace_timeout( wasp_timeout timeout ){
    wasp_grey_obj( (wasp_object) timeout->input );
}

WASP_GENERIC_COMPARE( timeout );
WASP_GENERIC_FORMAT( timeout );
WASP_GENERIC_FREE( timeout );
WASP_C_TYPE( timeout )

WASP_BEGIN_PRIM( "timeout", timeout )
    REQ_INTEGER_ARG( ms );
    REQ_INPUT_ARG( input );
    NO_REST_ARGS( );
    
    wasp_timeout timeout = wasp_make_timeout( ms, input );
    if( ms < 0 ) wasp_errf( wasp_es_vm, "si", "Negative timeouts are not allowed", ms );

    wasp_schedule_timeout( timeout, ms );
    TIMEOUT_RESULT( timeout ); 
WASP_END_PRIM( timeout )

WASP_BEGIN_PRIM( "cancel-timeout", cancel_timeout )
    REQ_TIMEOUT_ARG( timeout )
    NO_REST_ARGS( );
    
    wasp_cancel_timeout( timeout );
    
    NO_RESULT( );
WASP_END_PRIM( cancel_timeout )

void wasp_init_time_subsystem( ){
    WASP_I_TYPE( timeout );
    wasp_ss_timeout = wasp_symbol_fs( "timeout" );

    WASP_BIND_PRIM( timeout );
    WASP_BIND_PRIM( cancel_timeout );
}

