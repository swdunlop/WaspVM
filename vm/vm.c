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

void wasp_trace_step( );
wasp_primitive wasp_instr_table[ 32 ];

wasp_byte wasp_max_opcode = 0;

jmp_buf* wasp_interp_xp;
jmp_buf* wasp_proc_xp;

wasp_callframe   WASP_AP;
wasp_callframe   WASP_CP;
wasp_pair        WASP_EP;
wasp_pair        WASP_GP;
wasp_instruction WASP_IP;
wasp_value       WASP_RX;
wasp_integer     WASP_T = 0;

struct wasp_pool_data wasp_callframe_scrap_data;
wasp_pool wasp_callframe_scrap = &wasp_callframe_scrap_data;

wasp_callframe wasp_make_callframe( ){
    return (wasp_callframe) wasp_scavenge( wasp_callframe_type, wasp_callframe_scrap, sizeof( struct wasp_callframe_data ) );
}
void wasp_trace_registers( ){
    wasp_grey_obj( (wasp_object) WASP_AP );
    wasp_grey_obj( (wasp_object) WASP_CP );
    wasp_grey_obj( (wasp_object) WASP_EP );
    wasp_grey_obj( (wasp_object) WASP_GP );
    if( WASP_IP ) wasp_grey_obj( (wasp_object) WASP_IP->proc );
    wasp_grey_val( WASP_RX );
}
void wasp_bind_op( const char* name, wasp_prim_fn impl, 
                  wasp_boolean a, wasp_boolean b ){
    wasp_primitive prim = wasp_make_primitive( name, impl );
    prim->code = wasp_max_opcode;
    prim->a = a;
    prim->b = b;
    wasp_root_obj( (wasp_object) prim );
    wasp_instr_table[ wasp_max_opcode ++ ] = prim ;
}
wasp_primitive wasp_lookup_op( wasp_symbol name ){
    int i; 
    for( i = 0; i < wasp_max_opcode; i ++ ){
        if( wasp_instr_table[i]->name == name )return wasp_instr_table[i];
    }
    return NULL;
}
void wasp_interp_loop( ){
    // Only one interpreter loop is permitted in the current call stack; we
    // long jump back to it.
    if( wasp_interp_xp )return longjmp( *wasp_interp_xp, 102 );

    // An interp loop is only permitted subordinate to a process loop; if it
    // is absent, we will kick it off.
    if( ! wasp_proc_xp )return wasp_proc_loop( );

    jmp_buf exit; 
    wasp_interp_xp = &exit;
    setjmp( exit );
    
    while( WASP_IP ){
        if( WASP_T )wasp_trace_step();
        WASP_IP->prim->impl( );
        wasp_collect_window( );
    };
    
    wasp_disable_process( wasp_active_process );
    wasp_interp_xp = NULL;
}

#define WASP_AX ( WASP_IP->a )
#define WASP_BX ( WASP_IP->b )

void wasp_add_call_arg( wasp_value x ){
    wasp_pair p = wasp_cons( x, wasp_vf_null() );

    if(  WASP_AP->count++ ){
        wasp_set_cdr( WASP_AP->tail, wasp_vf_pair( p ) );
    }else{
        WASP_AP->head = p;
    }

    WASP_AP->tail = p;
}

void wasp_next_instr( ){ WASP_IP ++; }

void wasp_instr_arg( ){
  // (call-add-item! ap rx)
  // (set! ip (next-instr ip)) 
  
    wasp_add_call_arg( WASP_RX );
    wasp_next_instr( );
}
void wasp_instr_scat( ){
  // (for-each (lambda (rx) (call-add-item! ap rx))
  //           rx)
  // (set! ip (next-instr ip)) 
    
    wasp_pair p;
    for( p = wasp_req_list( WASP_RX ); p; p = wasp_req_list( wasp_cdr( p ) ) ){
        wasp_add_call_arg( wasp_car( p ) );
    }
    wasp_next_instr( );
}
void wasp_jump( ){
    if( ! WASP_CP->head ){
        wasp_errf( wasp_es_vm, "s", "cannot evaluate an empty application" );
    }

    wasp_value fn = wasp_car( WASP_CP->head );
    wasp_pair  args = wasp_list_fv( wasp_cdr( WASP_CP->head ) );
    wasp_integer ct = WASP_CP->count;

    fn = wasp_reduce_function( fn, args );
    
    if( wasp_is_closure( fn ) ){
        wasp_closure clos = wasp_closure_fv( fn );

        WASP_EP = wasp_clos_env( clos );
        WASP_IP = wasp_clos_inst( clos );
    }else if( wasp_is_primitive( fn ) ){
        wasp_arg_ptr = args;
        wasp_arg_ct = ct;
        WASP_AP = WASP_CP->ap;
        WASP_EP = WASP_CP->ep;
        WASP_IP = WASP_CP->ip;
        wasp_primitive_fv( fn )->impl();
        WASP_CP = WASP_CP->cp;
    }else if( wasp_is_procedure( fn ) ){
        WASP_EP = NULL;
        WASP_IP = wasp_procedure_fv( fn )->inst;
    }else{
        wasp_errf( wasp_es_vm, "sx", "cannot call non-function", fn );
    }
}
void wasp_instr_call( ){
    // Error if call frame is empty
    // (define fn   (call-fn ap))
    // (define args (call-args ap))

    // (if (is-closure? fn)
    //   (begin (set-call-cp! ap cp)
    //          (set-call-ep! ap ep)
    //          (set-call-gp! ap gp)
    //          (set-call-ip! ap (next-instr ip))
    //          (set! cp ap)
    //          (set! ep (closure-env fn))
    //          (set! ip (proc-instr (closure-proc fn))))
    //   (apply (prim-impl fn) args))
    
    WASP_AP->gp = WASP_GP;
    WASP_AP->cp = WASP_CP;
    WASP_AP->ep = WASP_EP;
    WASP_AP->ip = WASP_IP+1;
    WASP_CP = WASP_AP;
 
    wasp_jump( );
}
void wasp_instr_tail( ){
    // (define fn   (call-fn ap))
    // (define args (call-args ap))

    // (if (is-closure? fn) 
    //   (begin (set-call-data! cp (call-data ap)) 
    //          (set! ep (closure-env fn)) 
    //          (set! ip (proc-instr (closure-proc fn)))) 
    //   (apply (prim-impl fn) args)) 
     
    WASP_CP->head = WASP_AP->head;
    WASP_CP->tail = WASP_AP->tail;
    WASP_CP->count = WASP_AP->count;

    wasp_jump( );
}
void wasp_instr_clos( ){
    // (set! rx (make-closure ep ip))
    // (set! ip (instr-ax ip))
    // (set! ip (next-instr ip))

    WASP_RX = wasp_vf_closure( wasp_make_closure( 
        WASP_AX,
        WASP_IP+1,
        WASP_EP
    ) );

    WASP_IP = WASP_IP->proc->inst + wasp_imm_fv( WASP_BX );
}
void wasp_instr_gar( ){
    // (set! gp (cons (make-guard rx cp ap (instr-ax ip))
    //                gp))
    // (set! ip (next-instr ip))

    WASP_GP = wasp_cons( 
        wasp_vf_guard( wasp_make_guard( WASP_RX, WASP_CP, WASP_AP, WASP_EP, 
                                        WASP_IP->proc->inst + 
                                        wasp_imm_fv( WASP_AX ), WASP_T )), 
        wasp_vf_list( WASP_GP ) );

    wasp_next_instr();
}

void wasp_instr_jmp( ){
    // (set! ip ax)

    WASP_IP = WASP_IP->proc->inst + wasp_imm_fv( WASP_AX );
}
//TODO: Add the prog field to instructions
void wasp_instr_jf( ){
    // (if (eq? #f rx)
    //     (set! ip (instr-ax ip))
    //     (set! ip (next-instr ip)))

    if( wasp_is_false( WASP_RX ) ){
        WASP_IP = WASP_IP->proc->inst + wasp_imm_fv( WASP_AX );
    }else{
        wasp_next_instr();
    }
}
void wasp_instr_jt( ){
    // (if (eq? #f rx)
    //     (set! ip (next-instr ip))
    //     (set! ip (instr-ax ip)))

    if( wasp_is_false( WASP_RX ) ){
        wasp_next_instr();
    }else{
        WASP_IP = WASP_IP->proc->inst + wasp_imm_fv( WASP_AX );
    }
}
void wasp_instr_ldb( ){
    // (set! rx (vector-ref (list-ref ep (instr-ax ip))
    //          (instr-bx ip)))
    // (set! ip (next-instr ip))

    WASP_RX = wasp_vector_get( 
        wasp_vector_fv( 
            wasp_car( wasp_list_ref( WASP_EP, wasp_imm_fv( WASP_AX ) ) ) 
        ), 
        wasp_imm_fv( WASP_BX ) 
    );
    
    wasp_next_instr();
}
void wasp_instr_ldc( ){
    // (set! rx (instr-ax ip))
    // (set! ip (next-instr ip))
    WASP_RX = WASP_AX;

    wasp_next_instr();
}
void wasp_instr_ldg( ){
    // (set! rx (get-global (instr-ax ip)))
    // (set! ip (next-instr ip))
    
    wasp_symbol s = wasp_symbol_fv( WASP_AX );
    if( wasp_has_global( s ) ){
        WASP_RX = wasp_get_global( s );
    }else{
        wasp_errf( wasp_es_vm, "sx", "global not bound", s );
    }
    wasp_next_instr();
}
void wasp_instr_newf( ){
    // (set! ap (make-call-frame))
    // (set! ip (next-instr ip))
    wasp_callframe ap = WASP_AP;
    WASP_AP = wasp_make_callframe();
    WASP_AP->ap = ap; 

    wasp_next_instr();
}
void wasp_instr_rag( ){
    // (set! gp (cdr gp))
    // (set! ip (next-instr ip))

    WASP_GP = wasp_list_fv( wasp_cdr( WASP_GP ) );

    wasp_next_instr();
}
void wasp_instr_retn( ){
    // (set! ep (call-ep cp))
    // (set! ip (call-ip cp))
    // (set! cp (call-cp cp))
    if( WASP_CP ){
        WASP_EP = WASP_CP->ep;
        WASP_IP = WASP_CP->ip;
        WASP_AP = WASP_CP->ap;
        // FIX: Fix for non-local returns failing to restore the calling
        //      context's guard.
        WASP_GP = WASP_CP->gp;
        WASP_CP = WASP_CP->cp;
    }else{
        WASP_IP = NULL;
        wasp_interp_loop( );
    }
}
void wasp_instr_stb( ){
    // (vector-set! (list-ref ep (instr-ax ip)) 
    //              (instr-bx ip) 
    //              rx) 
    // (set! ip (next-instr ip)) 

    wasp_vector_put( wasp_vector_fv( wasp_car( wasp_list_ref( WASP_EP, 
                                            wasp_imm_fv( WASP_AX ) ) ) ),
                    wasp_imm_fv( WASP_BX ),
                    WASP_RX );
    wasp_next_instr();
}
void wasp_instr_stg( ){
    // (set-global (instr-ax ip) rx)
    // (set! ip (next-instr ip)) 
    wasp_set_global( wasp_symbol_fv( WASP_AX ), WASP_RX );
    wasp_next_instr();
}
void wasp_instr_usea( ){
    // (define max (instr-ax ip)) 
    wasp_word max = wasp_imm_fv( WASP_AX );

    if(( WASP_CP->count - 1 ) < max ){
        wasp_errf( wasp_es_vm, "sii", "argument underflow", WASP_CP->count, max );
    }

    // (define env (make-vector (instr-bx ip))) 
    wasp_vector env = wasp_make_vector( wasp_imm_fv( WASP_BX ) );

    // (let loop ((ix 0) 
    //            (args (call-args cp))) 
    //   (cond ((= ix max) (vector-set! env ix args)) 
    //         ((null? args)) ;;; Do nothing. 
    //         (else (vector-set! env ix (car args)) 
    //               (loop (+ ix 1) (cdr args))))) 

    wasp_word ix = 0;

    //TODO: Do we want to bind the function called?
    wasp_pair p = wasp_list_fv( wasp_cdr( WASP_CP->head ) );

    for(;;){
        if( ix == max ){
            wasp_vector_put( env, ix, wasp_vf_list( p ) );
            break;
        }else{
            wasp_vector_put( env, ix, wasp_car( p ) );
            p = wasp_list_fv( wasp_cdr( p ) );
            ix ++;
        }
    }

    // (set! ep (cons env ep)) 
    WASP_EP = wasp_cons( wasp_vf_vector( env ), wasp_vf_list( WASP_EP ) );

    // (set! ip (next-instr ip)) 
    wasp_next_instr( );
}
void wasp_instr_usen( ){
    wasp_word max = wasp_imm_fv( WASP_AX ) + 1;

    if( WASP_CP->count < max ){
        wasp_errf( wasp_es_vm, "sii", "argument underflow", WASP_CP->count, max );
    }else if( WASP_CP->count > max ){
        wasp_errf( wasp_es_vm, "sii", "argument overflow", WASP_CP->count, max );
    };

    // (define env (make-vector (instr-bx ip))) 
    wasp_vector env = wasp_make_vector( wasp_imm_fv( WASP_BX ) );

    // (let loop ((ix 0) 
    //            (args (call-args cp))) 
    //   (if (not (null? args)) 
    //     (vector-set! env ix (car args))) 
    //   (loop (+ ix 1) (cdr args))) 

    wasp_word ix = 0;
    //TODO: Do we want to bind the function called?
    wasp_pair p = wasp_list_fv( wasp_cdr( WASP_CP->head ) );

    while( p ){
        wasp_vector_put( env, ix, wasp_car( p ) );
        p = wasp_list_fv( wasp_cdr( p ) );
        ix ++;
    }

    // (set! ep (cons env ep)) 
    WASP_EP = wasp_cons( wasp_vf_vector( env ), wasp_vf_list( WASP_EP ) );

    // (set! ip (next-instr ip)) 
    wasp_next_instr( );
}

void wasp_trace_callframe( wasp_callframe cf ){
    wasp_grey_obj( (wasp_object) cf->ap );
    wasp_grey_obj( (wasp_object) cf->cp );
    wasp_grey_obj( (wasp_object) cf->ep );
    wasp_grey_obj( (wasp_object) cf->gp );
    if( cf->ip ) wasp_grey_obj( (wasp_object) cf->ip->proc );
    wasp_grey_obj( (wasp_object) cf->head );
    wasp_grey_obj( (wasp_object) cf->tail );
}

void wasp_free_callframe( wasp_object obj ){
    wasp_discard( obj, wasp_callframe_scrap );
}
WASP_GENERIC_COMPARE( callframe );
WASP_GENERIC_FORMAT( callframe );
WASP_C_TYPE2( callframe, "call-frame" )

wasp_symbol wasp_es_vm;

void wasp_init_vm_subsystem( ){
    WASP_I_TYPE( callframe );

    wasp_es_vm = wasp_symbol_fs( "vm" );
    //TODO: We need to get clever and build this statically.

#define WASP_BIND_OP( on, a, b ) \
    wasp_bind_op( #on, wasp_instr_##on, a, b )

    WASP_BIND_OP( arg,  0, 0); //00
    WASP_BIND_OP( call, 0, 0); //01
    WASP_BIND_OP( clos, 1, 1); //02
    WASP_BIND_OP( gar,  1, 0); //03
    WASP_BIND_OP( jf,   1, 0); //04
    WASP_BIND_OP( jmp,  1, 0); //05
    WASP_BIND_OP( jt,   1, 0); //06
    WASP_BIND_OP( ldb,  1, 1); //07
    WASP_BIND_OP( ldc,  1, 0); //08
    WASP_BIND_OP( ldg,  1, 0); //09 
    WASP_BIND_OP( newf, 0, 0); //0a
    WASP_BIND_OP( rag,  0, 0); //0b
    WASP_BIND_OP( retn, 0, 0); //0c
    WASP_BIND_OP( scat, 0, 0); //0d
    WASP_BIND_OP( stb,  1, 1); //0e
    WASP_BIND_OP( stg,  1, 0); //0f
    WASP_BIND_OP( tail, 0, 0); //10
    WASP_BIND_OP( usea, 1, 1); //11
    WASP_BIND_OP( usen, 1, 1); //12
}

#ifndef USE_OLD_TRACE
void wasp_trace_ip( wasp_instruction ip ){
    wasp_prim_fn p = ip->prim->impl;
    int ap = 0, rx = 0;
        
    if( p == wasp_instr_call ){
        ap = 1;
    }else if( p == wasp_instr_tail ){
        ap = 1;  
    }else if( p == wasp_instr_retn ){
        rx = 1; 
    }else return;

    int i = 0; wasp_callframe cp = WASP_CP;
    while( cp ){
        i ++; cp = cp->cp;
    };

    wasp_string s = wasp_make_string( 80 );
    wasp_string_append_indent( s, i );

    wasp_format_instruction( s, ip );
    wasp_string_append_cs( s, ": " );
    
    if( ap ){
        wasp_format_value( s, wasp_vf_obj( (wasp_object) WASP_AP->head ), 
                           32, 3 );
    }else if( rx ){
        wasp_format_value( s, WASP_RX, 32, 3 );
    }

    wasp_string_append_newline( s );

    //TODO: This might be better directed to a channel, or stderr..
    
    wasp_printstr( s );
    wasp_objfree( s );
}
#else
void wasp_trace_ip( wasp_instruction ip ){
    wasp_string s = wasp_make_string( 80 );
    wasp_string_append_hex( s, ip - ip->proc->inst );
    wasp_string_append_cs( s, ": " );
    wasp_format_instruction( s, ip );

    int ap = 0, rx = 0;
    
    if( p == wasp_instr_call ){
        ap = 1;
    }else if( p == wasp_instr_tail ){
        ap = 1;
    }else if(( p == wasp_instr_arg ) ||( p == wasp_instr_scat )) {
        ap = 1; rx = 1;
    }else if( p == wasp_instr_stb ){
        rx = 1;
    }else if( p == wasp_instr_stg ){
        rx = 1;
    }
    
    if( ap ){
        wasp_string_append_cs( s, " -- " );
        wasp_format_value( s, wasp_vf_obj( (wasp_object) WASP_AP->head ), 
                           32, 3 );
    }

    if( rx ){
        wasp_string_append_cs( s, " :: " );
        wasp_format_value( s, WASP_RX, 32, 3 );
    }

    wasp_string_append_newline( s );
    //TODO: This might be better directed to a channel, or stderr..
    wasp_printstr( s );
    wasp_objfree( s );
}
#endif

void wasp_chain( wasp_pair data ){
    if( ! WASP_CP ) WASP_CP = wasp_make_callframe( );
    WASP_CP->gp = WASP_GP;
    WASP_CP->head = data;
    WASP_CP->tail = wasp_last_pair( data );
    WASP_CP->count = wasp_list_length( data );
    wasp_jump( );
    wasp_interp_loop();
}
void wasp_chainf( wasp_value fn, wasp_word ct, ... ){
    va_list ap;
    wasp_tc tc = wasp_make_tc( );
    va_start( ap, ct );

    wasp_tc_add( tc, fn );

    while( ct -- ){
        wasp_tc_add( tc, va_arg( ap, wasp_value ) );
    }

    wasp_chain( tc->head );
}

void wasp_trace_step( ){
    wasp_trace_ip( WASP_IP );
}
wasp_value wasp_req_function( wasp_value v ){
    if( wasp_is_function( v ) )return v;
    wasp_errf( wasp_es_vm, "sx", "expected function", v );
}

