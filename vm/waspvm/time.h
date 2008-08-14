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
#include <event.h>

struct wasp_task_data;
typedef struct wasp_task_data* wasp_task;

typedef int (*wasp_task_mt)( wasp_task task );

struct wasp_task_data{ 
    struct wasp_object_data header;

    struct timeval time;
    struct event   event;

    wasp_task_mt   task_mt;
    wasp_value     context;

    int pending :1;
};

WASP_H_TYPE( task )

#define REQ_TASK_ARG( x ) REQ_TYPED_ARG( x, task )
#define OPT_TASK_ARG( x ) OPT_TYPED_ARG( x, task )
#define TASK_RESULT( x )  TYPED_RESULT( task, x )

extern wasp_symbol wasp_ss_task;

wasp_task wasp_make_task( wasp_task_mt mt, wasp_value context );
wasp_task wasp_schedule_task( wasp_task task, wasp_quad ms );
void wasp_cancel_task( wasp_task task );

void wasp_init_time_subsystem( );

#endif
