/* Copyright (C) 2006, Scott W. Dunlop <swdunlop@gmail.com>
 *
 * Portions Copyright (C) 2006, Ephemeral Security, furnished via the LGPL.
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

wasp_symbol wasp_ss_close;

void wasp_set_monitor( wasp_input channel, wasp_process process ){
    if( process->monitoring ){
        wasp_errf( wasp_es_vm, "sxx", 
                "a process may only monitor one input at a time",
                process, 
                channel );
    };
    
    if( channel->monitor ){
        wasp_errf( wasp_es_vm, "sxx", 
                "another process is already monitoring this channel",
                process, 
                channel->monitor,
                channel );
    }

    wasp_disable_process( process );
    process->monitoring = (wasp_object) channel;
    channel->monitor = process;
}

void wasp_clear_monitor( wasp_input channel ){
    if( channel->monitor == NULL ) return;
    channel->monitor->monitoring = NULL;
    channel->monitor = NULL;
}

int wasp_wake_process( wasp_process process, wasp_value message ){
    if( process ){ 
        if( process->monitoring ) 
            wasp_clear_monitor( (wasp_input) process->monitoring );
        wasp_enable_process( process );
        if( wasp_is_vm( process->context ) ){
            // A courtesy to vm processes..
            wasp_vm_fv( process->context )->rx = message;
            return 1;
        }
    }

    return 0;
}

wasp_boolean wasp_wake_monitor( wasp_input channel, wasp_value message ){   
    return wasp_wake_process( channel->monitor, message );
}

wasp_boolean wasp_input_monitored( wasp_input channel ){
    return (wasp_boolean)channel->monitor;
}

void wasp_channel_xmit( wasp_output channel, wasp_value data ){
    channel->xmit( channel, data );
}

void wasp_trace_input( wasp_input input ){
    if( wasp_input_monitored ) wasp_grey_obj( (wasp_object) input->monitor );
}

WASP_GENERIC_FREE( input );
WASP_GENERIC_COMPARE( input );
WASP_GENERIC_FORMAT( input );

WASP_C_TYPE( input );

WASP_GENERIC_MT( output );

WASP_C_TYPE( output );

WASP_BEGIN_PRIM( "send-output", send_output )
    REQ_ANY_ARG( data );
    OPT_OUTPUT_ARG( output );
    NO_REST_ARGS( );
    
    if( ! has_output ){
        output = wasp_req_output( 
            wasp_process_output( wasp_active_process )
        );
    };

    output->xmit( output, data );

    OUTPUT_RESULT( output );
WASP_END_PRIM( send_output )

WASP_BEGIN_PRIM( "wait-input", wait_input )
    wasp_value data;

    OPT_INPUT_ARG( input );
    NO_REST_ARGS( );

    if( ! has_input ){
        input = wasp_req_input( wasp_process_input( wasp_active_process ) );
    };

    if( ! input->recv( input, &data ) ){
        wasp_set_monitor( input, wasp_active_process );
	
        // The following statement ensures that wait will not be called again
        // when we return.
	
        WASP_CP = WASP_CP->cp;
	
        // Restart the process loop since the active has been suspended.  Does
        // not return.
	
        wasp_proc_loop( );
    }else{ 
        RESULT( data );
    }
WASP_END_PRIM( wait_input )

void wasp_init_channel_subsystem( ){
    WASP_I_TYPE( input );
    WASP_I_TYPE( output );
    
    WASP_BIND_PRIM( send_output )
    WASP_BIND_PRIM( wait_input )

    wasp_ss_close = wasp_symbol_fs( "close" );
}

