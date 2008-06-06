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
 * along with this library; if not, print to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef WASP_PROGRAM_H
#define WASP_PROGRAM_H 1

#include "waspvm.h"
#include <string.h>

wasp_integer wasp_instruction_code( wasp_primitive prim ){
    //TODO: This should be in the prim, along with uses_a, uses_b.
    wasp_integer i;
    for( i = 0; i <= wasp_max_opcode; i ++ ){
        if( wasp_instr_table[i] == prim ) break;
    }
    return i;
}

void wasp_format_instruction( wasp_string buf, wasp_instruction instr ){
    wasp_primitive prim = instr->prim;
    wasp_value a = instr->a;
    wasp_value b = instr->b;
    wasp_integer c = wasp_instruction_code( prim );
    
    wasp_string_append_byte( buf, '(' );
    wasp_string_append_sym( buf, wasp_prim_name( prim ) );

    if( prim->a ){
        wasp_string_append_byte( buf, ' ' );
        if( ! wasp_format_item( buf, instr->a ) )goto done;
    }

    if( prim->b ){
        wasp_string_append_byte( buf, ' ' );
        wasp_format_item( buf, instr->b );
    }
done:
    wasp_string_append_byte( buf, ')' );
}
wasp_procedure wasp_make_procedure( wasp_word length ){
    size_t tail = sizeof( struct wasp_instruction_data ) * length;
    wasp_procedure v = WASP_OBJALLOC2( procedure, tail );

    v->length = length;
    
    while( length ) v->inst[ -- length ].proc = v;

    return v;
}
void wasp_trace_procedure( wasp_procedure proc ){
    wasp_word i;
    for( i = 0; i < proc->length; i ++ ){
        wasp_word ct = 5; 
        wasp_instruction instr = wasp_procedure_ref( proc, i );
        wasp_grey_obj( (wasp_object) instr->prim );
        wasp_grey_val( instr->a );
        wasp_grey_val( instr->b );
    }
}

WASP_GENERIC_FORMAT( procedure );
WASP_GENERIC_COMPARE( procedure );
WASP_GENERIC_FREE( procedure );

WASP_C_TYPE( procedure );

WASP_BEGIN_PRIM( "assemble", assemble )
    REQ_LIST_ARG( source );
    NO_REST_ARGS( );
    PROCEDURE_RESULT( wasp_assemble( source ) );
WASP_END_PRIM( assemble )

void wasp_init_procedure_subsystem( ){
    WASP_I_TYPE( procedure );
    WASP_BIND_PRIM( assemble );
}

wasp_procedure wasp_assemble( wasp_list src ){
    wasp_integer index;
    wasp_pair p;
    wasp_primitive op;
    wasp_dict labels = wasp_make_dict( );
    index = 0; p = src;
    
    wasp_value parse_arg( wasp_value arg ){
        if( wasp_is_symbol( arg ) ){
            wasp_node node = wasp_tree_lookup( labels, arg );
            if( node )return wasp_cdr( wasp_pair_fv( node->data ) );
        };
        return arg;
    }

    while( p ){
        wasp_value line = wasp_car( p );

        if( wasp_is_pair( line ) ){
            wasp_pair l = wasp_pair_fv( line );
            index += 1;
            op = wasp_lookup_op( wasp_req_symbol( wasp_car( l ) ) );
            if( ! op ){ wasp_errf( wasp_es_vm, "sx", "unrecognized operator", l ); };
            wasp_integer len = wasp_list_length( l );
            if( len < 1 + op->a + op->b ){
                wasp_errf( wasp_es_vm, "sxi", "insufficent operands", op, len );
            }
        }else if( wasp_is_symbol( line ) ){
            wasp_tree_insert( 
                labels, wasp_vf_pair(
                    wasp_cons( line, wasp_vf_integer( index ) ) ) );
        }else{
            wasp_errf( wasp_es_vm, "s", "assemble requires a list of statements");
        };

        p = wasp_req_list( wasp_cdr( p ) );
    };
   
    if( ! index )wasp_errf( wasp_es_vm, "s", "empty source" );

    wasp_procedure proc = wasp_make_procedure( index );

    index = 0; p = src;

    while( p ){
        wasp_value line = wasp_car( p );

        if( wasp_is_pair( line ) ){
            wasp_pair l = wasp_pair_fv( line );
            op = wasp_lookup_op( wasp_symbol_fv( wasp_car( l ) ) );
            l = wasp_list_fv( wasp_cdr( l ) );
            proc->inst[index].prim = op;
            if( op->a ){
                proc->inst[index].a = parse_arg( wasp_car( l ) );
                l = wasp_list_fv( wasp_cdr( l ) );
            };
            if( op->b ){
                proc->inst[index].b = parse_arg( wasp_car( l ) );
            };
            index += 1;
        };

        p = wasp_req_list( wasp_cdr( p ) );
    };

    return proc;
}
#endif
