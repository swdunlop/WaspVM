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

// A re-implementation of the MOSVM Tree API to cross-check the possibly
// malfunctioning TAVL.

// By enabling WASP_AUDIT_TREES you will greatly reduce speed of the tree
// library, but a comprehensive audit of the two treap invariants will be
// performed after each insert and remove.

#ifdef WASP_AUDIT_TREES
#  ifdef NDEBUG
#    error "WASP_AUDIT_TREES requires NDEBUG not be set, since it uses asserts"
#  endif
#define WASP_AUDIT_TREE( tree ) wasp_audit_tree( tree ) 
#else
#define WASP_AUDIT_TREE( tree )
#endif

// Raises the left branch of a node to the position of that node.
wasp_node *wasp_raise_left( wasp_node* root ){
    wasp_node base = *root;
    wasp_node left = base->left;

    assert( left );
    
    base->left = left->right;
    left->right = base;
   
    *root = left;
    
    return &left->right;
}

// Raises the right branch of a node to the position of that node.
wasp_node *wasp_raise_right( wasp_node* root ){
    wasp_node base = *root;
    wasp_node right = base->right;
    
    assert( right );
    
    base->right = right->left;
    right->left = base;

    *root = right;

    return &right->left;
}

#ifdef WASP_AUDIT_TREES
void wasp_audit_node( wasp_node node, wasp_key_fn key_fn, wasp_integer *pct ){
    (*pct)++;

    wasp_value key = key_fn( node->data );
    
    if( node->left ){
        assert( node->left->weight >= node->weight );
        assert( wasp_cmp_eqv( key, key_fn( node->left->data ) ) > 0 );
        assert( wasp_cmp_eqv( key_fn( node->left->data ), key ) < 0 );
        wasp_audit_node( node->left, key_fn, pct );
    }

    if( node->right ){
        assert( node->right->weight >= node->weight );
        assert( wasp_cmp_eqv( key, key_fn( node->right->data ) ) < 0 );
        assert( wasp_cmp_eqv( key_fn( node->right->data ), key ) > 0 );
        wasp_audit_node( node->right, key_fn, pct );
    }
}
wasp_integer wasp_audit_tree( wasp_tree tree ){
    wasp_integer ct = 0;
    if( tree->root )wasp_audit_node( tree->root, tree->key_fn, &ct );
    return ct;
}
#endif

wasp_tree wasp_make_tree( wasp_type type, wasp_key_fn key_fn ){
    wasp_tree tree = (wasp_tree)wasp_objalloc( 
        type, sizeof( struct wasp_tree_data ) );
    tree->key_fn = key_fn;
    return tree;
}
wasp_dict wasp_make_dict( ){
    return wasp_make_tree( wasp_dict_type, wasp_dict_key );
}
wasp_set wasp_make_set( ){
    return wasp_make_tree( wasp_set_type, wasp_set_key );
}

wasp_node wasp_make_node( wasp_value data ){
    //TODO: we need to ensure that our random function was initialized.
    wasp_node node = malloc( sizeof( struct wasp_node_data ) );
    node->weight = rand();
    node->data = data;
    node->left = NULL;
    node->right = NULL;
    return node;
}

int wasp_insert_item_at( wasp_node* link, wasp_node* yield, wasp_value item, wasp_value key, wasp_key_fn key_fn ){
    //Internal routine to recurse down the tree, and either discover the
    //leaf closest to a new node, or a matching node.  Returns nonzero if a
    //node was created and rebalancing is required.
    //
    //This routine is recursive, therefore the C stack may overflow if
    //the number of nodes exceeds 100,000.  Effort is made to reduce the
    //amount of overhead per recursion by using GCC's nested functions.
    //
    // Returns 0 if the node was found.
    // Returns 1 if the node was made.

    wasp_node node = *link;

    if( ! node ){
        node = wasp_make_node( item );
        *link = node;
        *yield = node;
        return 1;
    };

    wasp_integer difference = wasp_cmp_eqv( key, key_fn( node->data ) );

    if( difference < 0 ){
        if( wasp_insert_item_at( &(node->left), yield, item, key, key_fn ) ){
            if( node->left->weight < node->weight ){
                wasp_raise_left( link ); return 1;
            };
        };
    }else if( difference > 0 ){
        if( wasp_insert_item_at( &(node->right), yield, item, key, key_fn ) ){
            if( node->right->weight < node->weight ){
                wasp_raise_right( link ); return 1;
            };
        };
    }else{
        *yield = node;
        node->data = item;
    };

    return 0;
}
    
wasp_node wasp_tree_insert( wasp_tree tree, wasp_value item ){
    wasp_node yield = NULL;

    wasp_insert_item_at( &(tree->root), &yield, item, tree->key_fn( item ), tree->key_fn );

    return yield;
}

int wasp_tree_remove( wasp_tree tree, wasp_value key ){
    wasp_key_fn key_fn = tree->key_fn;
    
    wasp_node* root = &(tree->root);
    wasp_node node;
    wasp_integer difference;

    for(;;){
        node = *root; 

        if( node == NULL ){
            return 0; // Node not found.
        }

        difference = wasp_cmp_eqv( key, key_fn( node->data ) );

        if( difference < 0 ){
            root = &(node->left);
        }else if( difference > 0 ){
            root = &(node->right);
        }else{
            break;
        } 
    }

    for(;;){
        if( node->left && node->right ){
            if( node->left->weight > node->right->weight ){
                wasp_raise_right( root );
                root = &((*root)->left);
            }else{
                wasp_raise_left( root );
                root = &((*root)->right);
            }
        }else if( node->left ){
            wasp_raise_left( root );
            root = &((*root)->right);
        }else if( node->right ){
            wasp_raise_right( root );
            root = &((*root)->left);
        }else{
            *root = NULL; 
        
            return 1;            
        }
    }
}

wasp_node wasp_tree_lookup( wasp_tree tree, wasp_value key ){
    wasp_key_fn key_fn = tree->key_fn;
    
    wasp_node node = tree->root;
    
    while( node ){
        if( node == NULL )return NULL; // Node not found.
            
        wasp_integer difference = wasp_cmp_eqv( key, key_fn( node->data ) );

        if( difference < 0 ){
            node = node->left;
        }else if( difference > 0 ){
            node = node->right;
        }else{
            break;
        } 
    }

    WASP_AUDIT_TREE( tree );

    return node;
}

void wasp_iter_node( wasp_node node, wasp_iter_mt iter, void* ctxt ){
    if( node == NULL )return;
    wasp_iter_node( node->left, iter, ctxt );
    iter( node->data, ctxt );
    wasp_iter_node( node->right, iter, ctxt );
}

void wasp_iter_tree( wasp_tree tree, wasp_iter_mt iter, void* ctxt ){
    wasp_iter_node( tree->root, iter, ctxt );
}

void wasp_format_tree_cb( wasp_value value, wasp_string buf ){
    wasp_string_append_byte( buf, ' ' );
    wasp_format_item( buf, value );
}

void wasp_format_tree( wasp_string buf, wasp_tree tree ){
    wasp_format_begin( buf, tree );
    wasp_iter_tree( tree, (wasp_iter_mt)wasp_format_tree_cb, buf );
    wasp_format_end( buf );
}

wasp_value wasp_set_key( wasp_value item ){ return item; }
wasp_value wasp_dict_key( wasp_value item ){
    return wasp_car( wasp_pair_fv( item ) );
}

void wasp_trace_node( wasp_node node ){
    if( node == NULL )return;
    wasp_grey_val( node->data );
    wasp_trace_node( node->left );
    wasp_trace_node( node->right );
}
void wasp_trace_tree( wasp_tree tree ){
    wasp_trace_node( tree->root );
}
void wasp_free_node( wasp_node node ){
    if( node == NULL )return;
    wasp_free_node( node->left );
    wasp_free_node( node->right );
    free( node );
}
void wasp_free_tree( wasp_tree tree ){
    wasp_free_node( tree->root );
    wasp_objfree( tree );
}

WASP_GENERIC_COMPARE( tree );
WASP_C_TYPE( tree );

WASP_INHERIT_GC( set, tree );
WASP_INHERIT_FORMAT( set, tree );
WASP_GENERIC_COMPARE( set );
WASP_C_TYPE( set );

WASP_INHERIT_GC( dict, tree );
WASP_INHERIT_FORMAT( dict, tree );
WASP_GENERIC_COMPARE( dict );
WASP_C_TYPE( dict );

void wasp_init_tree_subsystem( ){
    WASP_I_TYPE( tree );
    WASP_I_SUBTYPE( set, tree );
    WASP_I_SUBTYPE( dict, tree );
}

