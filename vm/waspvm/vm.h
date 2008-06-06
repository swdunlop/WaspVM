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

#ifndef WASP_VM_H
#define WASP_VM_H 1

#include "memory.h"
#include "primitive.h"
#include <setjmp.h>

WASP_BEGIN_TYPE( callframe )
    wasp_callframe   ap, cp;
    wasp_pair        gp, ep;
    wasp_instruction ip;
    wasp_word        count;
    wasp_pair        head, tail;
WASP_END_TYPE( callframe )

wasp_callframe wasp_make_callframe( );

extern wasp_callframe   WASP_AP;
extern wasp_callframe   WASP_CP;
extern wasp_pair        WASP_EP;
extern wasp_pair        WASP_GP;
extern wasp_instruction WASP_IP;
extern wasp_value       WASP_RX;
extern wasp_integer WASP_T;

extern wasp_primitive wasp_instr_table[];
extern wasp_boolean wasp_uses_a[];
extern wasp_boolean wasp_uses_b[];
extern wasp_byte wasp_max_opcode;

void wasp_inner_exec( );
void wasp_outer_exec( );

void wasp_trace_registers();
void wasp_init_vm_subsystem( );

extern wasp_symbol wasp_es_vm;

jmp_buf* wasp_interp_xp;
jmp_buf* wasp_proc_xp;

void wasp_chain( wasp_pair data );
void wasp_chainf( wasp_value fn, wasp_word ct, ... );
void wasp_interp_loop( );

wasp_primitive wasp_lookup_op( wasp_symbol name );
wasp_value wasp_req_function( wasp_value v );
wasp_value wasp_reduce_function( wasp_value fn, wasp_list args );
#endif 
