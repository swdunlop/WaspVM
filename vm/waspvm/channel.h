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

#ifndef WASP_CHANNEL_H
#define WASP_CHANNEL_H 1

#define WASP_CLOSE_EVT 1
#define WASP_XMIT_EVT  2
#define WASP_RECV_EVT  3
#define WASP_TIMEOUT_EVT 4

extern wasp_symbol wasp_ss_close;
extern wasp_symbol wasp_ss_channel; 

typedef void (*wasp_output_mt)( void*, wasp_value );
typedef wasp_byte (*wasp_input_mt)( void*, wasp_value* );
typedef void (*wasp_event_mt)( wasp_object context, unsigned int event );

WASP_BEGIN_TYPE( channel )
    // Intentionally left blank, channel is really an abstract base class.
WASP_END_TYPE( channel )

WASP_BEGIN_SUBTYPE( channel, input )
    wasp_input_mt recv;
    wasp_process first_mon, last_mon;
WASP_END_SUBTYPE( input )

/* A raw input yields strings of data, or 'close if the input has been closed. 
   The notify method is called when the buffer is empty. */

WASP_BEGIN_SUBTYPE( input, raw_input )
    int status; // 0 for in operation, -1 for closing, -2 for closed

    wasp_event_mt notify;
    wasp_string buffer;
    wasp_object context;
WASP_END_SUBTYPE( raw_input )

WASP_BEGIN_SUBTYPE( channel, output )
    wasp_output_mt xmit;
WASP_END_SUBTYPE( output )

/* A raw output accepts strings of data, or 'close to direct the output to 
   close.  The notify method is called when data is appended to the buffer, 
   or when the channel is close'd with an empty buffer. */

WASP_BEGIN_SUBTYPE( output, raw_output )
    int status; // 0 for in operation, -1 for closing, -2 for closed
    
    wasp_event_mt notify;
    wasp_string buffer;
    wasp_object context;
WASP_END_SUBTYPE( raw_output )

#define REQ_CHANNEL_ARG( vn ) REQ_SUBTYPED_ARG( vn, channel )
#define OPT_CHANNEL_ARG( vn ) OPT_SUBTYPED_ARG( vn, channel )
#define CHANNEL_RESULT( vn )  TYPED_RESULT( channel, vn )

#define REQ_INPUT_ARG( vn ) REQ_SUBTYPED_ARG( vn, input )
#define OPT_INPUT_ARG( vn ) OPT_SUBTYPED_ARG( vn, input )
#define INPUT_RESULT( vn )  TYPED_RESULT( input, vn )

#define REQ_OUTPUT_ARG( vn ) REQ_SUBTYPED_ARG( vn, output )
#define OPT_OUTPUT_ARG( vn ) OPT_SUBTYPED_ARG( vn, output )
#define OUTPUT_RESULT( vn )  TYPED_RESULT( output, vn )

/* Called when we need to initalize a raw input */

void wasp_init_raw_input( wasp_raw_input raw, wasp_event_mt notify, 
			   wasp_object context );

wasp_raw_input wasp_make_raw_input( wasp_event_mt notify, wasp_object context );

/* Called when we need to initalize a raw output */

void wasp_init_raw_output( wasp_raw_output raw, wasp_event_mt notify,
			    wasp_object context );

wasp_raw_output wasp_make_raw_output( wasp_event_mt notify, wasp_object context );

/* Called when an input is being monitored; wakes the first monitor with
 * the new message in RX.
 */

wasp_boolean wasp_wake_monitor( wasp_input channel, wasp_value message );

/* Predicate testing whether an input is being monitored by one or more
 * processes.
 */

wasp_boolean wasp_input_monitored( wasp_input input );

/* Initializes the channel subsystem, part of the core. */

void wasp_init_channel_subsystem( );

// The following three functions are intended for use by primitive routines operating on
// raw channels.

/* Reads pending input in a raw output channel. If channel is closed, 
   datalen will be -1, and the returned char* will be NULL. */

const char* wasp_read_raw_output( wasp_raw_output raw, unsigned int* datalen );

/* Signals a raw input channel closed. */
void wasp_close_raw_input( wasp_raw_input raw );

/* Adds data to a raw input channel. */
void wasp_append_raw_input( wasp_raw_input raw, 
			     const char* data, 
			     unsigned int datalen );


#endif
