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

WASP_BEGIN_TYPE( input )
    wasp_input_mt recv;
    wasp_process first_mon, last_mon;
WASP_END_TYPE( input )

WASP_BEGIN_TYPE( output )
    wasp_output_mt xmit;
WASP_END_TYPE( output )

wasp_boolean wasp_wake_monitor( wasp_input channel, wasp_value message );

/* Predicate testing whether an input is being monitored by one or more
 * processes. */
wasp_boolean wasp_input_monitored( wasp_input input );

/* Initializes the channel subsystem, part of the core. */
void wasp_init_channel_subsystem( );

#define REQ_CHANNEL_ARG( vn ) REQ_SUBTYPED_ARG( vn, channel )
#define OPT_CHANNEL_ARG( vn ) OPT_SUBTYPED_ARG( vn, channel )
#define CHANNEL_RESULT( vn )  TYPED_RESULT( channel, vn )

#define REQ_INPUT_ARG( vn ) REQ_SUBTYPED_ARG( vn, input )
#define OPT_INPUT_ARG( vn ) OPT_SUBTYPED_ARG( vn, input )
#define INPUT_RESULT( vn )  TYPED_RESULT( input, vn )

#define REQ_OUTPUT_ARG( vn ) REQ_SUBTYPED_ARG( vn, output )
#define OPT_OUTPUT_ARG( vn ) OPT_SUBTYPED_ARG( vn, output )
#define OUTPUT_RESULT( vn )  TYPED_RESULT( output, vn )

#endif
