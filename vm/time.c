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
//TODO:WIN32:TASK
#else
void wasp_task_cb( int fd, short evt, void* context ){
    wasp_task task = (wasp_task) context; 
    int ms = task->task_mt( task );

    if( ms ){
        task->time.tv_sec = ms / 1000;
        task->time.tv_usec = ((ms % 1000)) * 1000;
        evtimer_add( &( task->event ), &( task->time ) );
    }else{
        wasp_unroot_obj( (wasp_object) task );
    };
}
#endif

wasp_task wasp_make_task( wasp_task_mt mt, wasp_value context ){
    wasp_task task = WASP_OBJALLOC( task );
#ifdef WASP_IN_WIN32
	//TODO:WIN32:TASK
#else
    evtimer_set( &( task->event ), wasp_task_cb, task );
#endif
    task->task_mt = mt;
    task->context = context;
    return task;
}

wasp_task wasp_schedule_task( wasp_task task, wasp_quad ms ){
    wasp_root_obj( (wasp_object) task );
#ifdef WASP_IN_WIN32
	//TODO:WIN32:TASK
#else
    task->time.tv_sec = ms / 1000;
    task->time.tv_usec = ((ms % 1000)) * 1000;
    evtimer_add( &( task->event ), &( task->time ) );
#endif
}

void wasp_cancel_task( wasp_task task ){
#ifdef WASP_IN_WIN32
	//TODO:WIN32:TASK
#else
    evtimer_del( &( task->event ) );
#endif
    wasp_unroot_obj( (wasp_object) task );
}

void wasp_trace_task( wasp_task task ){
    wasp_grey_val( task->context );
}

WASP_GENERIC_COMPARE( task );
WASP_GENERIC_FORMAT( task );
WASP_GENERIC_FREE( task );
WASP_C_TYPE( task )

int wasp_timeout_mt( wasp_task task ){
    wasp_input input = wasp_input_fv( task->context );
    
    if( wasp_input_monitored( input ) ){
        wasp_wake_monitor( input, wasp_vf_symbol( wasp_ss_timeout ) );
    };
    
    return 0;
}

WASP_BEGIN_PRIM( "timeout", timeout )
    REQ_INTEGER_ARG( ms );
    REQ_INPUT_ARG( input );
    NO_REST_ARGS( );
    
    wasp_task task = wasp_make_task( wasp_timeout_mt, wasp_vf_input( input ) );
    
    if( ms < 0 ) wasp_errf( wasp_es_vm, "si", "Negative timeouts are not allowed", ms );

    wasp_schedule_task( task, ms );
    TASK_RESULT( task ); 
WASP_END_PRIM( timeout )

WASP_BEGIN_PRIM( "cancel-task", cancel_task )
    REQ_TASK_ARG( task )
    NO_REST_ARGS( );
    
    wasp_cancel_task( task );
    
    NO_RESULT( );
WASP_END_PRIM( cancel_task )

int wasp_pause_mt( wasp_task task ){
    wasp_enable_process( wasp_process_fv( task->context ) );
    return 0;
}

WASP_BEGIN_PRIM( "pause", pause )
    wasp_value data;

    OPT_INTEGER_ARG( ms );
    NO_REST_ARGS( );

    // The following statement ensures that pause will not be called again
    // when we return.
    WASP_CP = WASP_CP->cp;

    // No result for when we return.
    WASP_RX = wasp_vf_null( );

    wasp_process p = wasp_active_process;
    wasp_disable_process( p );
        
    if( ! has_ms ){
        wasp_enable_process( p );
    }else{ 
        wasp_task task = wasp_make_task( wasp_pause_mt, wasp_vf_process( p ) );
        wasp_schedule_task( task, ms );
    }

    // Restart the process loop since the active has been suspended.  Does
    // not return.
    wasp_proc_loop( );
WASP_END_PRIM( pause )

void wasp_init_time_subsystem( ){
    WASP_I_TYPE( task );
    wasp_ss_timeout = wasp_symbol_fs( "timeout" );

    WASP_BIND_PRIM( timeout );
    WASP_BIND_PRIM( cancel_task );
    WASP_BIND_PRIM( pause );
}

