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

#ifndef WASP_CLOSURE_H
#define WASP_CLOSURE_H 1

#include "memory.h"
#include "procedure.h"

WASP_BEGIN_TYPE( closure )
    wasp_value     name;
    wasp_instruction inst;
    wasp_pair      env;
WASP_END_TYPE( closure )

#define REQ_CLOSURE_ARG( vn ) REQ_TYPED_ARG( vn, closure )
#define CLOSURE_RESULT( vn ) TYPED_RESULT( vn, closure )
#define OPT_CLOSURE_ARG( vn ) OPT_TYPED_ARG( vn, closure )

static inline wasp_value wasp_clos_name( wasp_closure clos ){ 
    return clos->name;
}
static inline wasp_instruction wasp_clos_inst( wasp_closure clos ){
    return clos->inst;
}
static inline wasp_pair wasp_clos_env( wasp_closure clos ){
    return clos->env;
}

wasp_closure wasp_make_closure( wasp_value name, wasp_instruction inst, wasp_pair env );
wasp_value wasp_function_name( wasp_value function );
void wasp_format_func( wasp_string buf, wasp_value func );

void wasp_init_closure_subsystem( );

#endif
