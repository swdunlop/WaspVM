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

#ifndef WASP_BOOLEAN_H
#define WASP_BOOLEAN_H 1

#include "memory.h"

extern wasp_value wasp_the_true;
extern wasp_value wasp_the_false;

WASP_H_TP( boolean );
WASP_H_IS( boolean );
#define REQ_BOOLEAN_ARG( vn ) REQ_TYPED_ARG( vn, boolean )
#define BOOLEAN_RESULT( vn ) TYPED_RESULT( boolean, vn )
#define OPT_TYPE_ARG( vn ) OPT_TYPED_ARG( vn, type )
#define TRUE_RESULT( ) RESULT( wasp_vf_true( ) );
#define FALSE_RESULT( ) RESULT( wasp_vf_false( ) );

static inline wasp_value wasp_vf_false( ){ return wasp_the_false; }
static inline wasp_value wasp_vf_true( ){ return wasp_the_true; }
static inline wasp_value wasp_vf_boolean( wasp_boolean q ){
    return q ? wasp_the_true : wasp_the_false;
}
static inline wasp_boolean wasp_is_false( wasp_value v ){
    return v == wasp_the_false;
}
static inline wasp_boolean wasp_is_true( wasp_value v ){
    return v == wasp_the_true;
}

void wasp_init_boolean_subsystem( );

#endif
