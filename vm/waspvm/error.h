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

#ifndef WASP_ERROR_H
#define WASP_ERROR_H 1

#include "memory.h"

WASP_BEGIN_TYPE( error )
    wasp_symbol key;
    wasp_pair   info, context;
WASP_END_TYPE( error )

WASP_BEGIN_TYPE( guard )
    wasp_value fn;
    wasp_callframe ap, cp;
    wasp_instruction ip;
    wasp_pair ep;
    wasp_integer t;
WASP_END_TYPE( guard )

#define REQ_ERROR_ARG( vn ) REQ_TYPED_ARG( vn, error )
#define ERROR_RESULT( vn ) TYPED_RESULT( vn, error )
#define OPT_ERROR_ARG( vn ) OPT_TYPED_ARG( vn, error )

#define REQ_GUARD_ARG( vn ) REQ_TYPED_ARG( vn, guard )
#define GUARD_RESULT( vn ) TYPED_RESULT( vn, guard )
#define OPT_GUARD_ARG( vn ) OPT_TYPED_ARG( vn, guard )

void wasp_errf( wasp_symbol key, const char* fmt, ... );
void wasp_show_error( wasp_error e, wasp_word* ct );
void wasp_format_traceback( wasp_string buf, wasp_error e );
int wasp_format_context( wasp_string buf, wasp_list context  );
wasp_error wasp_make_error( wasp_symbol key, wasp_list info, wasp_list context );
wasp_pair wasp_frame_context( wasp_callframe callframe );
void wasp_throw_error( wasp_error e );

wasp_guard wasp_make_guard( 
    wasp_value fn, wasp_callframe cp, wasp_callframe ap, wasp_pair ep, 
    wasp_instruction ip, wasp_integer t
);

void wasp_init_error_subsystem( );

#endif
