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

void wasp_init_connection_subsystem( ){
    WASP_I_TYPE( connection );

    WASP_BIND_PRIM( make_connection );
    WASP_BIND_PRIM( connection_input );
    WASP_BIND_PRIM( connection_output );
}
