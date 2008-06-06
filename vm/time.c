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


wasp_timeout wasp_first_timeout = NULL;
wasp_timeout wasp_last_timeout = NULL;
wasp_process wasp_timemon;

int wasp_timeout_compare( wasp_timeout t1, wasp_timeout t2 ){
    if( t1->secs > t2->secs ) return 1;
    if( t1->secs < t2->secs ) return -1;
    if( t1->nsecs < t2->nsecs ) return 1;
    if( t1->nsecs < t2->nsecs ) return -1;
    return 0;
}

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
wasp_timeout wasp_make_timeout( 
    wasp_quad ms, wasp_output output, wasp_value signal  
){
    wasp_quad secs, nsecs; wasp_get_now( &secs, &nsecs );
    secs += (ms / 1000);
    nsecs += ((ms % 1000) * 1000); // 1,000 ns per ms
    wasp_timeout timeout = WASP_OBJALLOC( timeout );
    timeout->secs = secs;
    timeout->nsecs = nsecs;
    timeout->output = output;
    timeout->signal = signal;
    return timeout;
}

void wasp_enable_timeout( wasp_timeout new ){
    wasp_timeout timeout, next, prev;

    if( wasp_first_timeout == NULL ){
        wasp_enable_process( wasp_timemon );
    }else for( timeout = wasp_first_timeout; timeout; timeout = next ){
        next = timeout->next;

        if( wasp_timeout_compare( new, timeout ) < 0 ){
            prev = timeout->prev;
            if( prev ){
                prev->next = new;
            }else{
                wasp_first_timeout = new;
            }
            new->prev = prev;
            timeout->prev = new;
            new->next = timeout;

            return;
        }
    }

    if( wasp_last_timeout  ){
        wasp_last_timeout->next = new;
    }else{
        wasp_first_timeout = new;
    }

    new->prev = wasp_last_timeout;
    wasp_last_timeout = new;
}

void wasp_disable_timeout( wasp_timeout timeout ){
    wasp_timeout prev = timeout->prev;
    wasp_timeout next = timeout->next;
    if( prev ){
        prev->next = next;
    }else{
        wasp_first_timeout = next;
    };
    if( next ){
        next->prev = prev;
    }else{
        wasp_last_timeout = prev;
    }
    timeout->prev = timeout->next = NULL;
}
void wasp_trace_timeout( wasp_timeout timeout ){
    wasp_grey_obj( (wasp_object) timeout->output );
    wasp_grey_val( timeout->signal );
}
void wasp_trace_timeouts( ){
    wasp_timeout timeout, next;
    
    for( timeout = wasp_first_timeout; timeout; timeout = next ){
        next = timeout->next;
        wasp_grey_obj( (wasp_object) timeout );
    }
}
void wasp_invoke_timeout( wasp_timeout timeout ){
    timeout->output->xmit( timeout->output, timeout->signal );
    wasp_disable_timeout( timeout );
}

void wasp_activate_timemon( wasp_process process, wasp_value context ){
    wasp_timeout timeout, next;
    
    wasp_quad secs, nsecs; wasp_get_now( &secs, &nsecs );
    
    for( timeout = wasp_first_timeout; timeout; timeout = next ){
        next = timeout->next;
        if( timeout->secs < secs ){
            wasp_invoke_timeout( timeout );
        }else if( timeout->secs == secs ){
            if( timeout->nsecs <= nsecs ){
                wasp_invoke_timeout( timeout );
            }
        };
    }

    if( wasp_first_timeout == NULL ){
        assert( wasp_last_timeout == NULL );
        wasp_disable_process( wasp_timemon );
    }
}

void wasp_deactivate_timemon( wasp_process process, wasp_value context ){ }

WASP_GENERIC_FORMAT( timeout );
WASP_GENERIC_FREE( timeout );
WASP_C_TYPE( timeout )

WASP_BEGIN_PRIM( "timeout", timeout )
    REQ_INTEGER_ARG( ms );
    REQ_OUTPUT_ARG( output );
    REQ_ANY_ARG( message );
    NO_REST_ARGS( );
    
    wasp_timeout timeout = ( wasp_make_timeout( ms, output, message ) ); 
    wasp_enable_timeout( timeout );
    TIMEOUT_RESULT( timeout ); 
WASP_END_PRIM( timeout )

WASP_BEGIN_PRIM( "cancel-timeout", cancel_timeout )
    REQ_TIMEOUT_ARG( timeout )
    NO_REST_ARGS( );
    
    wasp_disable_timeout( timeout );
    
    NO_RESULT( );
WASP_END_PRIM( cancel_timeout )

int wasp_any_timeouts( ){
    return wasp_first_timeout != NULL;
}

void wasp_init_time_subsystem( ){
    WASP_I_TYPE( timeout );
    wasp_timemon = wasp_make_process( 
        (wasp_proc_fn) wasp_activate_timemon, 
        (wasp_proc_fn) wasp_deactivate_timemon, 
        wasp_vf_null( ) 
    );
    wasp_root_obj( (wasp_object) wasp_timemon );
    WASP_BIND_PRIM( timeout );
    WASP_BIND_PRIM( cancel_timeout );
}

