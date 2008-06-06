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
#ifndef WASP_TIME_H
#define WASP_TIME_H 1

#include "memory.h"

WASP_BEGIN_TYPE( timeout )
    wasp_quad secs, nsecs;
    wasp_output output;
    wasp_value   signal;
    wasp_timeout prev, next;
WASP_END_TYPE( timeout )

wasp_timeout wasp_make_timeout( 
    wasp_quad ms, wasp_output output, wasp_value signal  
);

void wasp_trace_timeouts();
void wasp_init_time_subsystem( );
int wasp_any_timeouts();

#define REQ_TIMEOUT_ARG( x ) REQ_TYPED_ARG( x, timeout )
#define OPT_TIMEOUT_ARG( x ) OPT_TYPED_ARG( x, timeout )
#define TIMEOUT_RESULT( x )  TYPED_RESULT( timeout, x )

#endif
