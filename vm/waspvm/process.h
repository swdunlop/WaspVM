/* Copyright (C) 2006, Ephemeral Security, LLC
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

#ifndef WASP_PROCESS_H
#define WASP_PROCESS_H 1

#include "memory.h"

#define WASP_IDLE_PROCESS 0
#define WASP_POLL_PROCESS 1
#define WASP_ACTIVE_PROCESS 2

typedef void (*wasp_proc_fn)(wasp_object process, wasp_value context );

WASP_BEGIN_TYPE( process )
    wasp_value name;
    wasp_process prev, next;
    wasp_proc_fn activate, deactivate;
    wasp_value context;
    wasp_byte state;
    wasp_object monitoring; //TODO: This is a channel..
    wasp_value input, output;
WASP_END_TYPE( process )

WASP_BEGIN_TYPE( vm )
    wasp_instruction ip;
    wasp_callframe   ap, cp;
    wasp_list        ep, gp;
    wasp_value       rx;
    int              t;
WASP_END_TYPE( vm )

wasp_process wasp_make_process( 
    wasp_proc_fn activate, wasp_proc_fn deactivate, wasp_value context 
);
wasp_process wasp_make_poll( wasp_proc_fn activate, wasp_value context );

void wasp_trace_process( wasp_process process );

wasp_vm wasp_make_vm( );
void wasp_trace_vm( wasp_vm vm );

void wasp_trace_actives( );
void wasp_dump_actives( );

void wasp_enable_process( wasp_process process );
void wasp_disable_process( wasp_process process );

void wasp_proc_loop( );

wasp_process wasp_spawn_call( wasp_pair call );
wasp_process wasp_spawn_thunk( wasp_value func );

wasp_value wasp_process_input( wasp_process process );
wasp_value wasp_process_output( wasp_process process );
void wasp_set_process_input( wasp_process process, wasp_value input );
void wasp_set_process_output( wasp_process process, wasp_value output );
void wasp_init_process_subsystem( );

extern wasp_process wasp_active_process;

extern wasp_process wasp_first_enabled;
extern wasp_process wasp_last_enabled;
extern wasp_process wasp_active_process;

#define REQ_PROCESS_ARG( x ) REQ_TYPED_ARG( x, process )
#define OPT_PROCESS_ARG( x ) OPT_TYPED_ARG( x, process )
#define PROCESS_RESULT( x )  TYPED_RESULT( process, x )

#endif
