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

#ifndef WASP_CONNECTION_H
#define WASP_CONNECTION_H 1

/** a simple combination of input and output; often used as a base class for communication
    with the host environment. */

WASP_BEGIN_TYPE( connection )
    wasp_input input;
    wasp_output output;
WASP_END_TYPE( connection );

#define REQ_CONNECTION_ARG( x ) REQ_SUBTYPED_ARG( x, connection )
#define OPT_CONNECTION_ARG( x ) OPT_SUBTYPED_ARG( x, connection )
#define CONNECTION_RESULT( x )  TYPED_RESULT( connection, x )

void wasp_init_connection( wasp_connection conn, wasp_input input, wasp_output output );
wasp_connection wasp_make_connection( wasp_input input, wasp_output output );

void wasp_init_connection_subsystem( );

#endif
