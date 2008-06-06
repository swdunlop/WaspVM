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

#ifndef WASP_INTEGER_H
#define WASP_INTEGER_H 1

#include "memory.h"

struct wasp_number_data {
    struct wasp_object_data header;

    wasp_integer intval;
};
typedef struct wasp_number_data* wasp_number;

WASP_H_TP( number );
WASP_H_VF( number );

wasp_number wasp_nf_integer( wasp_integer x );
wasp_integer wasp_integer_fn( wasp_number x );

WASP_H_RQ( integer );
WASP_H_RQ( number );

#define REQ_INTEGER_ARG( vn ) wasp_integer vn = wasp_req_intarg( );
#define INTEGER_RESULT( vn )  RESULT( wasp_vf_integer( vn ) );
#define OPT_INTEGER_ARG( vn ) \
    wasp_boolean has_##vn; \
    wasp_integer vn = wasp_opt_intarg( &has_##vn );

wasp_boolean wasp_is_integer( wasp_value val );
wasp_boolean wasp_is_number( wasp_value val );
wasp_value wasp_vf_integer( wasp_integer ix );
wasp_integer wasp_integer_fv( wasp_value val );

wasp_integer wasp_number_compare( wasp_value a, wasp_value b );
wasp_integer wasp_req_intarg( );
wasp_integer wasp_opt_intarg( );

void wasp_init_number_subsystem( );

#endif
