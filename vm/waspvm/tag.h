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

#ifndef WASP_TAG_H
#define WASP_TAG_H

#include "memory.h"

WASP_BEGIN_TYPE( tag )
    wasp_symbol name;
    wasp_value info;
WASP_END_TYPE( tag )

WASP_BEGIN_TYPE( cell )
    wasp_tag tag;
    wasp_value repr;
WASP_END_TYPE( cell )

#define REQ_TAG_ARG( vn ) REQ_TYPED_ARG( vn, tag )
#define TAG_RESULT( vn ) TYPED_RESULT( tag, vn )
#define OPT_TAG_ARG( vn ) OPT_TYPED_ARG( vn, tag )

#define REQ_CELL_ARG( vn ) REQ_TYPED_ARG( vn, cell )
#define CELL_RESULT( vn ) TYPED_RESULT( cell, vn )
#define OPT_CELL_ARG( vn ) OPT_TYPED_ARG( vn, cell )

void wasp_init_tag_subsystem( );
wasp_boolean wasp_isaq( wasp_value x, wasp_value t );
#endif
