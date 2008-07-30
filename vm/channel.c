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

wasp_symbol wasp_ss_channel;
wasp_symbol wasp_ss_close;

void wasp_add_monitor( wasp_process process, wasp_input channel ){
    if( process->monitoring ){
        wasp_errf( wasp_es_vm, "sxxx", 
                "a process may only monitor one input at a time",
                process, 
                process->monitoring,
                channel );
    };

    wasp_disable_process( process );
    process->monitoring = (wasp_object) channel;
   
    wasp_process prev = channel->last_mon;
    process->prev = prev;

    if( prev ){
        prev->next = process;
    }else{
        channel->first_mon = process;
    };
    
    channel->last_mon = process;
}

void wasp_remove_monitor( wasp_process process, wasp_input channel ){
    wasp_process first, prev, next;

    assert( channel == (wasp_input)(process->monitoring) );

    first = channel->first_mon;
    next = process->next;
    prev = process->prev;

    assert( first );

    if( prev ){ prev->next = next; process->prev = NULL; }else{
        channel->first_mon = next;
    };
    if( next ){ next->prev = prev; process->next = NULL; }else{
        channel->last_mon = prev;
    };

    process->monitoring = NULL;
}

void wasp_clear_monitor( wasp_process process ){
    wasp_remove_monitor( process, (wasp_input) process->monitoring );
}

wasp_boolean wasp_wake_monitor( wasp_input channel, wasp_value message ){   
    wasp_process process = channel->first_mon;

    if( process ){ 
        wasp_clear_monitor( process );
        wasp_enable_process( process );
        if( wasp_is_vm( process->context ) ){
            // A courtesy to vm processes..
            wasp_vm_fv( process->context )->rx = message;
            return 1;
        }
    }

    return 0;
}

wasp_boolean wasp_input_monitored( wasp_input channel ){
    return (wasp_boolean)channel->first_mon;
}

void wasp_channel_xmit( wasp_output channel, wasp_value data ){
    channel->xmit( channel, data );
}

WASP_GENERIC_TRACE( channel );
WASP_GENERIC_FREE( channel );
WASP_GENERIC_COMPARE( channel );
WASP_GENERIC_FORMAT( channel );
WASP_C_TYPE( channel )

void wasp_trace_input( wasp_input input ){
    wasp_process m;

    for( m = input->first_mon; m; m = m->next ){
        wasp_grey_obj( (wasp_object) m );
    }
}

WASP_GENERIC_FREE( input );
WASP_GENERIC_COMPARE( input );
WASP_GENERIC_FORMAT( input );

WASP_C_SUBTYPE2( input, "input", channel );

WASP_GENERIC_MT( output );

WASP_C_SUBTYPE2( output, "output", channel );

void wasp_trace_raw_input( wasp_raw_input input ){
    wasp_trace_input( (wasp_input) input );
    wasp_grey_obj( (wasp_object) input->buffer );
    if( input->context )wasp_grey_obj( input->context );
}

void wasp_free_raw_input( wasp_raw_input raw ){ }

// WASP_GENERIC_FREE( raw_input );
WASP_GENERIC_COMPARE( raw_input );
WASP_GENERIC_FORMAT( raw_input );
WASP_C_SUBTYPE2( raw_input, "raw-input", input );

void wasp_trace_raw_output( wasp_raw_output output ){
    wasp_grey_obj( (wasp_object) output->buffer );
    if( output->context )wasp_grey_obj( output->context );
}

WASP_GENERIC_FREE( raw_output );
WASP_GENERIC_COMPARE( raw_output );
WASP_GENERIC_FORMAT( raw_output );
WASP_C_SUBTYPE2( raw_output, "raw-output", output );

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
        wasp_add_monitor( wasp_active_process, input );

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

int wasp_raw_input_recv( wasp_raw_input input, wasp_value* data ){
    if( ! wasp_string_empty( input->buffer ) ){
	return wasp_raw_output_recv_ine( input, data );
    }else switch( input->status ){
    case -2:
	input->status = -1; // Probably an error, here..
    case -1:
	*data = wasp_vf_symbol( wasp_ss_close );
	return 1;
    default:
	// We just hit the low water recv mark, and we haven't closed.. 
        // Threaten the notify method!
	input->notify( input->context, WASP_RECV_EVT );
	if( ! wasp_string_empty( input->buffer ) ){
	    // Give up..
	    return wasp_raw_output_recv_ine( input, data );
	}else if( input->status < 0 ){
	    // Looks like we got closed at the last minute..
	    *data = wasp_vf_symbol( wasp_ss_close );
	    input->status = -1;
	    return 1;
	}
    }
}

void wasp_raw_output_xmit( wasp_raw_output output, wasp_value data ){
    if( wasp_is_symbol( data ) 
	&& ( wasp_ss_close == wasp_symbol_fv( data ) ) 
    ){
	if( output->status < 0 ) return;
	    
	if( wasp_string_empty( output->buffer ) ){
	    output->status = -1;
	    output->notify( output->context, WASP_CLOSE_EVT );
	}else{
	    output->status = -2;
	}
    }else if( wasp_is_string( data ) ){
	int was_empty = wasp_string_empty( output->buffer );
	wasp_string_append_str( output->buffer, wasp_string_fv( data ) );
	if( was_empty ) output->notify( output->context, WASP_XMIT_EVT ); 
    }else{
	wasp_errf( wasp_ss_channel, "sxx"
		    "Only strings and the symbol close may be transmitted to"
		    " raw output channels.",
		    output, data );
    }
}


wasp_raw_output wasp_make_raw_output( wasp_event_mt notify, wasp_object context ){
    wasp_raw_output raw = WASP_OBJALLOC( raw_output );
    wasp_init_raw_output( raw, notify, context );
    return raw;
}

void wasp_init_raw_output( wasp_raw_output raw, wasp_event_mt notify, 
			    wasp_object context 
){
    raw->notify = notify;
    raw->context = context;
    raw->buffer = wasp_make_string( 256 );
    raw->output.xmit = (wasp_output_mt) wasp_raw_output_xmit;
}

wasp_raw_input wasp_make_raw_input( wasp_event_mt notify, wasp_object context ){
    wasp_raw_input raw = WASP_OBJALLOC( raw_input );
    wasp_init_raw_input( raw, notify, context );
    return raw;
}

void wasp_init_raw_input( wasp_raw_input raw, wasp_event_mt notify,
			    wasp_object context 
){
    raw->notify = notify;
    raw->context = context;
    raw->buffer = wasp_make_string( 256 );
    raw->input.recv = (wasp_input_mt) wasp_raw_input_recv;
}

const char* wasp_read_raw_output( wasp_raw_output raw, unsigned int* datalen ){
    if( raw->status == -1 ){
	*datalen = -1;
	return NULL;
    }else if( wasp_string_empty( raw->buffer ) ){
	if( raw->status == -2 ){
	    raw->status = *datalen = -1;
	}else{
	    *datalen = 0;
	}
	return NULL;
    }else{
	return wasp_string_read( raw->buffer, datalen );
    }
}

void wasp_close_raw_input( wasp_raw_input raw ){
    switch( raw->status ){
    case -1:
    case -2:
	return;
    default:
	if( wasp_string_empty( raw->buffer ) ){
	    raw->status = -1;
	    
	    if( wasp_input_monitored( (wasp_input) raw ) ){
		wasp_wake_monitor( (wasp_input) raw, 
                                   wasp_vf_symbol( wasp_ss_close ) );
            }
	}else{
	    raw->status = -2;
	}
    }
}

void wasp_append_raw_input( wasp_raw_input raw, 
			     const char* data, 
			     unsigned int datalen 
){
    wasp_string_append( raw->buffer, data, datalen );
    
    if( datalen && wasp_input_monitored( (wasp_input) raw ) ){
	wasp_wake_monitor( (wasp_input) raw, 
                           wasp_vf_string( 
			     wasp_reads_string( raw->buffer ) ) );
    }
}

// ine is short for "is not empty"
int wasp_raw_output_recv_ine( wasp_raw_input input, wasp_value* data ){
   *data = wasp_vf_string( wasp_reads_string( input->buffer ) );

   return 1;
}

void wasp_init_channel_subsystem( ){
    WASP_I_TYPE( channel );
    WASP_I_SUBTYPE( input, channel );
    WASP_I_SUBTYPE( output, channel );
    WASP_I_SUBTYPE( raw_input, input );
    WASP_I_SUBTYPE( raw_output, output );
    
    WASP_BIND_PRIM( send_output )
    WASP_BIND_PRIM( wait_input )

    wasp_ss_close = wasp_symbol_fs( "close" );
    wasp_ss_channel = wasp_symbol_fs( "channel" );
}

