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

#include "waspvm.h"
#include <setjmp.h>
#include <stdarg.h>

wasp_quad wasp_vm_count = 0;
wasp_process wasp_first_enabled = NULL;
wasp_process wasp_last_enabled = NULL;
wasp_process wasp_active_process = NULL;

wasp_symbol wasp_sym_builtin;
wasp_symbol wasp_sym_program;

void wasp_activate_vm( wasp_process process, wasp_vm vm );
void wasp_activate_netmon( wasp_process process, wasp_object );

void wasp_format_process( wasp_string buf, wasp_process p ){
    wasp_format_begin( buf, p );
    wasp_string_append_byte( buf, ' ' );
    wasp_format_item( buf, p->name );
    wasp_format_end( buf );
}

WASP_GENERIC_FREE( process );
WASP_GENERIC_COMPARE( process );

void wasp_dump_actives( ){
    int i = 0;
    wasp_process p = wasp_first_enabled;
    while( p ){
        if( p == wasp_active_process ){
            wasp_printf( "sisxn", "ACTIVE ", i++, ":  ", p );
        }else{
            wasp_printf( "sisxn", "PROCESS ", i++, ": ", p );
        }
        p = p->next;
    };
}

void wasp_trace_actives( ){
    wasp_grey_obj( (wasp_object) wasp_first_enabled );
}

wasp_process wasp_make_process( 
    wasp_proc_fn activate, wasp_proc_fn deactivate, wasp_value context 
){
    wasp_process process = WASP_OBJALLOC( process );
    process->activate = activate;
    process->deactivate = deactivate;
    process->context = context;
    process->prev = process->next = NULL;
    process->enabled = 0;
    process->monitoring = NULL;
    process->name = wasp_vf_symbol( wasp_sym_builtin );
    if( wasp_active_process ){
        process->input = wasp_active_process->input;
        process->output = wasp_active_process->output;
    }else{
        process->input = 0;
        process->output = 0;
    };
    return process;
}

wasp_vm wasp_make_vm( ){
    wasp_vm vm = WASP_OBJALLOC( vm );
    return vm;
}

wasp_value wasp_process_input( wasp_process process ){
    return process->input;
}
wasp_value wasp_process_output( wasp_process process ){
    return process->output;
}
void wasp_set_process_input( wasp_process process, wasp_value input ){
    process->input = input;
}
void wasp_set_process_output( wasp_process process, wasp_value output ){
    process->output = output;
}
void wasp_enable_process( wasp_process process ){
    if( process->enabled )return; 
    
    if( wasp_is_vm( process->context ) ) wasp_vm_count ++;

    process->enabled = 1;
    process->next = NULL;
    process->prev = wasp_last_enabled;

    if( wasp_last_enabled ){
        wasp_last_enabled->next = process;
        wasp_last_enabled = process;
    }else{
        wasp_first_enabled = process;
        wasp_last_enabled = process;
    }
}

void wasp_disable_process( wasp_process process ){
    if( ! process->enabled )return; 

    if( wasp_is_vm( process->context ) ) wasp_vm_count --;

    wasp_process prev = process->prev;
    wasp_process next = process->next;
    process->enabled = 0;
   
    if( prev ){
        prev->next = next;
    }else{
        wasp_first_enabled = next;
    };

    if( next ){
        next->prev = prev;
    }else{
        wasp_last_enabled = prev;
    }
    
    process->next = process->prev = NULL;
}

void wasp_proc_loop( ){
    if( wasp_proc_xp ){
        // This means a subordinate process tried to return to the proc loop;
        // we kill the interpreter exit point, then rejoin the proc loop.
        wasp_interp_xp = NULL;

        if( wasp_active_process ){
            wasp_active_process->deactivate( (wasp_object) wasp_active_process,
                                              wasp_active_process->context );
        }
            
        longjmp( *wasp_proc_xp, 101 );
    }

    jmp_buf exit; 
    wasp_proc_xp = &exit;
    setjmp( exit ); 

    while( wasp_first_enabled ){
        wasp_active_process = wasp_first_enabled;
        while( wasp_active_process ){
            wasp_active_process->activate( (wasp_object) wasp_active_process,
                                           wasp_active_process->context );
            wasp_active_process->deactivate( (wasp_object) wasp_active_process,
                                             wasp_active_process->context );
            wasp_active_process = wasp_active_process->next;
        }
    }

    wasp_proc_xp = NULL;
}

void wasp_load_vm( wasp_vm vm ){
    WASP_IP = vm->ip;
    WASP_AP = vm->ap;
    WASP_CP = vm->cp;
    WASP_EP = vm->ep;
    WASP_GP = vm->gp;
    WASP_RX = vm->rx;
    WASP_T = vm->t;
}

void wasp_save_vm( wasp_vm vm ){
    vm->ip = WASP_IP;
    vm->ap = WASP_AP;
    vm->cp = WASP_CP;
    vm->ep = WASP_EP;
    vm->gp = WASP_GP;
    vm->rx = WASP_RX;
    vm->t = WASP_T;
}

void wasp_activate_vm( wasp_process process, wasp_vm vm ){
    wasp_load_vm( vm );
    if( WASP_T ){
        wasp_printf( "sxsn", "::: PROCESS ", process, " ACTIVATED :::" );
    }
    wasp_interp_loop( );
}

void wasp_deactivate_vm( wasp_process process, wasp_vm vm ){
    if( WASP_T ){
        wasp_printf( "sxsn", "::: PROCESS ", process, " DEACTIVATED :::" );
    }
    wasp_save_vm( vm );
}

void wasp_activate_prim( wasp_process process, wasp_list call ){
    WASP_AP = NULL;
    WASP_CP = NULL;
    WASP_EP = NULL;
    WASP_GP = NULL;
    WASP_IP = NULL;

    wasp_chain( call );
    if( WASP_IP ){
        //TEST: This permits a primitive to chain into a procedure that
        //      can pause.
        wasp_vm vm = wasp_make_vm( ); wasp_save_vm( vm );
        process->activate = (wasp_proc_fn) wasp_activate_vm;
        process->deactivate = (wasp_proc_fn) wasp_deactivate_vm;
        process->context = wasp_vf_vm( vm );
    }else{
        wasp_disable_process( process );
    }
}

void wasp_deactivate_prim( wasp_process process, wasp_list call ){
    return;
}

wasp_process wasp_spawn_call( wasp_pair call ){
    wasp_list rest = wasp_list_fv( wasp_cdr( call ) );
    wasp_value func = wasp_reduce_function( wasp_car( call ), rest );
    call = wasp_cons( func, wasp_vf_list( rest ) );
    wasp_process p;

    if( wasp_is_primitive( func ) ){
        p = wasp_make_process( (wasp_proc_fn)wasp_activate_prim, 
                              (wasp_proc_fn)wasp_deactivate_prim,
                              wasp_vf_list( call ) );
        p->name = wasp_vf_symbol( wasp_primitive_fv( func )->name );
    }else{
        wasp_vm vm = wasp_make_vm( );
        p = wasp_make_process( (wasp_proc_fn)wasp_activate_vm, 
                              (wasp_proc_fn)wasp_deactivate_vm, 
                              wasp_vf_vm( vm ) );

        vm->cp = wasp_make_callframe();
        vm->cp->head = call;
        vm->cp->tail = wasp_last_pair( call );
        vm->cp->count = wasp_list_length( call );
        vm->t = WASP_T;
        if( wasp_is_closure( func ) ){
            wasp_closure c = wasp_closure_fv( func );
            p->name = c->name;
            vm->ep = c->env;
            vm->ip = c->inst;
        }else if( wasp_is_procedure( func ) ){
            p->name = wasp_vf_symbol( wasp_sym_program );
            vm->ip = wasp_procedure_fv( func )->inst;
        }else{
            wasp_errf( wasp_es_vm, "sx", "only functions can be spawned", func );
        }
    };
   
    wasp_enable_process( p );

    return p;
}

wasp_process wasp_spawn_thunk( wasp_value thunk ){
    wasp_spawn_call( wasp_cons( thunk, wasp_vf_null( ) ) );
}

void wasp_trace_process( wasp_process process ){
    wasp_grey_val( (wasp_value) process->name );
    wasp_grey_obj( (wasp_object) process->prev );
    wasp_grey_obj( (wasp_object) process->next );
    wasp_grey_obj( (wasp_object) process->context );
    wasp_grey_obj( (wasp_object) process->monitoring );
    wasp_grey_val( process->input );
    wasp_grey_val( process->output );
}

WASP_C_TYPE( process );

void wasp_trace_vm( wasp_vm vm ){
    if( vm->ip )wasp_grey_obj( (wasp_object) vm->ip->proc );
    wasp_grey_obj( (wasp_object) vm->ap );
    wasp_grey_obj( (wasp_object) vm->cp );
    wasp_grey_obj( (wasp_object) vm->ep );
    wasp_grey_obj( (wasp_object) vm->gp );
    wasp_grey_val( vm->rx );
}

WASP_GENERIC_FREE( vm );
WASP_GENERIC_FORMAT( vm );
WASP_GENERIC_COMPARE( vm );
WASP_C_TYPE( vm );

WASP_BEGIN_PRIM( "spawn", spawn )
    REQ_FUNCTION_ARG( func )
    REST_ARGS( args );
     
    wasp_process p = wasp_spawn_call( wasp_cons( func, wasp_vf_list( args ) ) );

    wasp_set_process_output( p, wasp_process_output( wasp_active_process ) );
    wasp_set_process_input( p, wasp_process_input( wasp_active_process ) );

    PROCESS_RESULT( p );
WASP_END_PRIM( spawn )

WASP_BEGIN_PRIM( "halt", halt )
    NO_REST_ARGS( );
    wasp_disable_process( wasp_active_process );
    wasp_proc_loop( );
    NO_RESULT( );
WASP_END_PRIM( halt )

WASP_BEGIN_PRIM( "current-input", current_input )
    NO_REST_ARGS( );

    RESULT( wasp_active_process->input );
WASP_END_PRIM( current_input )

WASP_BEGIN_PRIM( "current-output", current_output )
    NO_REST_ARGS( );

    RESULT( wasp_active_process->output );
WASP_END_PRIM( current_output )

WASP_BEGIN_PRIM( "process-input", process_input )
    REQ_PROCESS_ARG( process );
    NO_REST_ARGS( );

    RESULT( process->input );
WASP_END_PRIM( process_input )

WASP_BEGIN_PRIM( "process-output", process_output )
    REQ_PROCESS_ARG( process );
    NO_REST_ARGS( );

    RESULT( process->output );
WASP_END_PRIM( process_output )

WASP_BEGIN_PRIM( "set-current-input!", set_current_input )
    REQ_INPUT_ARG( input );
    NO_REST_ARGS( );
    
    wasp_active_process->input = wasp_vf_input( input );
    NO_RESULT( );
WASP_END_PRIM( set_current_input )

WASP_BEGIN_PRIM( "set-current-output!", set_current_output )
    REQ_OUTPUT_ARG( output );
    NO_REST_ARGS( );

    wasp_active_process->output = wasp_vf_output( output );
    NO_RESULT( );
WASP_END_PRIM( set_current_output )

WASP_BEGIN_PRIM( "set-process-input!", set_process_input )
    REQ_PROCESS_ARG( process );
    REQ_INPUT_ARG( input );
    NO_REST_ARGS( );
    
    process->input = wasp_vf_input( input );
    NO_RESULT( );
WASP_END_PRIM( set_process_input )

WASP_BEGIN_PRIM( "set-process-output!", set_process_output )
    REQ_PROCESS_ARG( process );
    REQ_OUTPUT_ARG( output );
    NO_REST_ARGS( );

    process->output = wasp_vf_output( output );
    NO_RESULT( );
WASP_END_PRIM( set_process_output )

WASP_BEGIN_PRIM( "current-process", current_process )
    NO_REST_ARGS( );
    PROCESS_RESULT( wasp_active_process );
WASP_END_PRIM( current_process )

WASP_BEGIN_PRIM( "dump-actives", dump_actives )
    NO_REST_ARGS( );
    
    wasp_dump_actives( );

    NO_RESULT( );
WASP_END_PRIM( dump_actives )

void wasp_init_process_subsystem( ){
    WASP_I_TYPE( process );
    WASP_I_TYPE( vm );

    wasp_sym_builtin = wasp_symbol_fs( "builtin" );
    wasp_sym_program = wasp_symbol_fs( "program" );

    WASP_BIND_PRIM( spawn );
    WASP_BIND_PRIM( halt );
    WASP_BIND_PRIM( current_process );
    WASP_BIND_PRIM( current_input );
    WASP_BIND_PRIM( current_output );
    WASP_BIND_PRIM( process_input );
    WASP_BIND_PRIM( process_output );
    WASP_BIND_PRIM( set_current_input )
    WASP_BIND_PRIM( set_current_output )
    WASP_BIND_PRIM( set_process_input )
    WASP_BIND_PRIM( set_process_output )

    WASP_BIND_PRIM( dump_actives );
}
