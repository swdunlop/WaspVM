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

void wasp_init_connection( wasp_connection c, wasp_input i, wasp_output o ){
    c->input = i;
    c->output = o;
}

wasp_connection wasp_make_connection( wasp_input i, wasp_output o ){
    wasp_connection c = WASP_OBJALLOC( connection );
    wasp_init_connection( c, i, o );
    return c;
}

void wasp_trace_connection( wasp_connection c ){
    wasp_grey_obj( (wasp_object) c->input );
    wasp_grey_obj( (wasp_object) c->output );
}

WASP_GENERIC_FREE( connection )

WASP_GENERIC_FORMAT( connection );
WASP_GENERIC_COMPARE( connection );
WASP_C_TYPE( connection );

WASP_BEGIN_PRIM( "make-connection", make_connection )
    REQ_INPUT_ARG( input );
    REQ_OUTPUT_ARG( output );
    NO_REST_ARGS( );

    CONNECTION_RESULT( wasp_make_connection( input, output ) );
WASP_END_PRIM( make_connection );

WASP_BEGIN_PRIM( "connection-input", connection_input )
    REQ_CONNECTION_ARG( connection );
    NO_REST_ARGS( );

    RESULT( wasp_vf_input( connection->input ) );
WASP_END_PRIM( connection_input );

WASP_BEGIN_PRIM( "connection-output", connection_output )
    REQ_CONNECTION_ARG( connection );
    NO_REST_ARGS( );

    RESULT( wasp_vf_output( connection->output ) );
WASP_END_PRIM( connection_output );

#ifdef WASP_USE_SYNC_TERM
#include <stdio.h>
#include <string.h>

wasp_input wasp_stdin;
wasp_output wasp_stdout;

void wasp_sync_term_notify( wasp_connection c, unsigned int event ){
    const char* data;
    unsigned int datalen = 16384;
    char buffer[ 16385 ]; 

    switch( event ){
    case WASP_XMIT_EVT:
        data = wasp_read_raw_output( (wasp_raw_output) c->output, &datalen );
        fputs( data, stdout );
        break;
    case WASP_RECV_EVT:
        if( ! fgets( buffer, 16384, stdin ) ){ 
            wasp_close_raw_input( (wasp_raw_input) c->input );
            return;
        };

        wasp_append_raw_input( (wasp_raw_input) c->input, buffer, 
                               strlen( buffer ) );
        break;
    case WASP_CLOSE_EVT:
	// Don't care.
        break;
    }
}


wasp_connection wasp_make_sync_term( ){
    wasp_connection conn = wasp_make_connection( NULL, NULL );

    wasp_stdin = (wasp_input) wasp_make_raw_input( 
        (wasp_event_mt) wasp_sync_term_notify, (wasp_object) conn 
    );

    wasp_stdout = (wasp_output) wasp_make_raw_output( 
        (wasp_event_mt) wasp_sync_term_notify, (wasp_object) conn 
    );
    
    wasp_root_obj( (wasp_object) wasp_stdin ); 
    wasp_root_obj( (wasp_object) wasp_stdout ); 

    conn->input = wasp_stdin;
    conn->output = wasp_stdout;

    return conn;
};
#endif

void wasp_init_connection_subsystem( ){
    WASP_I_TYPE( connection );

    WASP_BIND_PRIM( make_connection );
    WASP_BIND_PRIM( connection_input );
    WASP_BIND_PRIM( connection_output );

#ifdef WASP_USE_SYNC_TERM    
    wasp_set_global( wasp_symbol_fs( "*console*" ), 
                     wasp_vf_connection( wasp_make_sync_term( ) ) );
#endif
}
