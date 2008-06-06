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

#ifndef WASP_TREE_H
#define WASP_TREE_H

#include "memory.h"

struct wasp_node_data;
typedef struct wasp_node_data* wasp_node;
struct wasp_node_data{
    wasp_quad weight;
    wasp_value data;
    wasp_node left, right;
};

typedef wasp_value (*wasp_key_fn) (wasp_value);

WASP_BEGIN_TYPE( tree )
    wasp_node root;
    wasp_key_fn key_fn;
WASP_END_TYPE( tree )
#define REQ_TREE_ARG( vn ) REQ_TYPED_ARG( vn, tree )
#define TREE_RESULT( vn ) TYPED_RESULT( vn, tree )
#define OPT_TREE_ARG( vn ) OPT_TYPED_ARG( vn, tree )

typedef wasp_tree wasp_set;
WASP_H_TYPE( set )
#define REQ_SET_ARG( vn ) REQ_TYPED_ARG( vn, set )
#define SET_RESULT( vn ) TYPED_RESULT( vn, set )
#define OPT_SET_ARG( vn ) OPT_TYPED_ARG( vn, set )

typedef wasp_tree wasp_dict;
WASP_H_TYPE( dict )
#define REQ_DICT_ARG( vn ) REQ_TYPED_ARG( vn, dict )
#define DICT_RESULT( vn ) TYPED_RESULT( vn, dict )
#define OPT_DICT_ARG( vn ) OPT_TYPED_ARG( vn, dict )

wasp_value wasp_set_key( wasp_value item );
wasp_value wasp_dict_key( wasp_value item ); 

/* A Warning about Keys and Items:
   For trees where key_of is not an identity function, any Item key will be
   passed to key_of to identify what key would be associated with the item.

   For example, an associative array derived from wasp_tree would want to ensure
   that invocations of wasp_insert_value uses a pair of index and value, not
   just index or value.
*/

wasp_tree wasp_make_tree( wasp_type type, wasp_key_fn key_fn );
wasp_dict wasp_make_dict( );
wasp_set wasp_make_set( );

wasp_node wasp_tree_insert(wasp_tree tree, wasp_value item);
int wasp_tree_remove(wasp_tree tree, wasp_value key);
wasp_node wasp_tree_lookup(wasp_tree tree, wasp_value key);

typedef void (*wasp_iter_mt)( wasp_value, void* );

void wasp_iter_tree(wasp_tree tree, wasp_iter_mt iter, void* ctxt );
void wasp_show_tree( wasp_tree tree, wasp_word* word );

void wasp_init_tree_subsystem( );

#endif
