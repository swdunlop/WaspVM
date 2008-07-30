/* Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
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

#ifndef WASP_OS_H
#define WASP_OS_H 1

#include "memory.h"
#ifdef WASP_IN_WIN32
	//TODO:WIN32:IO
#else
#include <event.h>
#endif

WASP_BEGIN_SUBTYPE( connection, os_connection )
#ifdef WASP_IN_WIN32
	//TODO:WIN32:IO
#else
    struct bufferevent* event;
#endif
    int handle;
    int closed: 1;
WASP_END_SUBTYPE( os_connection )

WASP_BEGIN_SUBTYPE( input, os_input )
    wasp_os_connection conn;
WASP_END_SUBTYPE( os_input )

WASP_BEGIN_SUBTYPE( output, os_output )
    wasp_os_connection conn;
WASP_END_SUBTYPE( os_output )

WASP_BEGIN_SUBTYPE( input, os_service )
#ifdef WASP_IN_WIN32
	//TODO:WIN32:SVR
#else
    struct event event;
    struct timeval timeval;
#endif
    int handle;

    int closed: 1;
    int timeout: 1;
WASP_END_SUBTYPE( os_service );

#define REQ_OS_CONNECTION_ARG( x ) REQ_TYPED_ARG( x, os_connection )
#define OPT_OS_CONNECTION_ARG( x ) OPT_TYPED_ARG( x, os_connection )
#define OS_CONNECTION_RESULT( x )  TYPED_RESULT( os_connection, x )

#define REQ_OS_SERVICE_ARG( x ) REQ_TYPED_ARG( x, os_service )
#define OPT_OS_SERVICE_ARG( x ) OPT_TYPED_ARG( x, os_service )
#define OS_SERVICE_RESULT( x )  TYPED_RESULT( os_service, x )

wasp_os_service wasp_make_os_service( int handle );
wasp_os_connection wasp_make_os_connection( int handle );

void wasp_init_os_subsystem( );

#endif
