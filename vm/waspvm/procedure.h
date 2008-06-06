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

#ifndef WASP_PROCEDURE_H
#define WASP_PROCEDURE_H 1

#include "memory.h"

struct wasp_procedure_data;
typedef struct wasp_procedure_data* wasp_procedure_x;

struct wasp_instruction_data {
    // Each instruction in the procedure refers to the procedure object; this
    // permits a closures and the virtual machine to not bother with managing
    // both a procedure pointer and an instruction pointer.

    wasp_procedure_x proc;
    wasp_primitive  prim;
    wasp_value a;
    wasp_value b;
}; 
typedef struct wasp_instruction_data* wasp_instruction;

WASP_BEGIN_TYPE( procedure )
    wasp_word length;
    struct wasp_instruction_data inst[0];
WASP_END_TYPE( procedure )
#define REQ_PROCEDURE_ARG( vn ) REQ_TYPED_ARG( vn, procedure )
#define PROCEDURE_RESULT( vn ) TYPED_RESULT( procedure, vn )
#define OPT_PROCEDURE_ARG( vn ) OPT_TYPED_ARG( vn, procedure )

wasp_procedure wasp_make_procedure( wasp_word length );
void wasp_dump_procedure( wasp_procedure procedure );
wasp_procedure wasp_assemble( wasp_pair source );

static inline wasp_instruction wasp_procedure_ref( 
    wasp_procedure procedure, wasp_word index 
){ 
    assert( index < procedure->length ); return procedure->inst + index; 
}

static inline wasp_word wasp_procedure_set(
    wasp_procedure procedure, wasp_word index, wasp_primitive prim, 
    wasp_value a, wasp_value b 
){
    wasp_instruction instr = wasp_procedure_ref( procedure, index );
    instr->prim = prim;
    instr->a = a;
    instr->b = b;
}

void wasp_format_instruction( wasp_string buf, wasp_instruction x );

void wasp_init_procedure_subsystem( );

#endif
