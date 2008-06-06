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

#define PKG_IOBJ    0
#define PKG_PAIR    1
#define PKG_PROC    2
#define PKG_LIST    3
#define PKG_STR     4
#define PKG_SYM     5

#ifdef WASP_IN_MINGW
// We need hton and ntoh
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
wasp_symbol wasp_es_pkg;

const char* wasp_mem_underflow = "memory underflow";

static inline wasp_boolean is_thaw_imm( wasp_word w ){ return w >= 0x8000; }
static inline wasp_word thaw_imm( wasp_word w ){ return w - 0x8000; }
static inline wasp_boolean is_thaw_ref( wasp_word w ){
    if( is_thaw_imm( w ) )return 0;
    return w < 0x7FFC;
}

wasp_value wasp_thaw_mem( const void* mem, wasp_quad memlen ){
    wasp_quad   memix  = 0;
    wasp_vector values = NULL;
    
    void err( const char* m ){ wasp_errf( wasp_es_pkg, "s", m ); };
                               
    const void* next_block( wasp_word len ){
        const char* p = mem + memix;
        memix += len;
        if( memix > memlen )err( wasp_mem_underflow );
        return p;
    }

    wasp_byte next_byte( ){
        return *(wasp_byte*)next_block( 1 );
    }
    wasp_word next_word( ){
        return ntohs( *(wasp_word*)next_block( 2 ) );
    }
    wasp_quad next_quad( ){
        return ntohl( *(wasp_quad*)next_block( 4 ) );
    }
    
    wasp_word   record_ct = next_word( );
    
    wasp_value vf_word( wasp_word w ){
        if( is_thaw_imm( w ) )return wasp_vf_integer( w - 0x8000 );
        if( w == 0x7FFF ) return wasp_vf_null( );
        if( w == 0x7FFD ) return wasp_vf_false( );
        if( w == 0x7FFC ) return wasp_vf_true( );
        return wasp_vector_get( values, w );
    };

    if( ! is_thaw_ref( record_ct ) ) return vf_word( record_ct );

    values = wasp_make_vector( record_ct );
   
    wasp_word record_ix = 0;
    wasp_word ln;

    while( record_ix < record_ct ){
        switch( next_byte() ){
        case PKG_IOBJ:  // Integer
            wasp_vector_put( values, record_ix, wasp_vf_integer( next_quad() ) ); 
            break;
        case PKG_PAIR:  // Pair
            next_word(); 
            next_word();
            wasp_vector_put( 
                values, record_ix, 
                wasp_vf_pair( wasp_cons( wasp_vf_null(), wasp_vf_null() ) ) );
            break;
        case PKG_PROC: // Procedure
            // Vicious, dirty.. We assume the procedure is probably much
            // longer than it is..
            ln = next_word();
            next_block( ln );
            wasp_vector_put( 
                values, record_ix, 
                wasp_vf_procedure( wasp_make_procedure( ln ) ) ); 
            break;
        case PKG_LIST: // List
            ln = next_word();
            next_block( ln * 2 );
            wasp_vector_put( 
                values, record_ix, 
                wasp_vf_pair( wasp_cons( wasp_vf_null(), wasp_vf_null() ) ) );
            break;
        case PKG_STR: // String
            ln = next_word();
            wasp_vector_put(
                values, record_ix,
                wasp_vf_string( wasp_string_fm( next_block(ln), ln ) ) );
            break;
        case PKG_SYM: // Symbol
            ln = next_word();
            wasp_vector_put( 
                values, record_ix, 
                wasp_vf_symbol( wasp_symbol_fm( next_block(ln), ln ) ) );
            break;
        default:
            err( "bad record type" );
        }
        record_ix ++;
    }

    wasp_pair pair, next;
    wasp_word ix;

    memix = 0; record_ix = 0; next_word();
    
    while( record_ix < record_ct ){
        switch( next_byte() ){
        case PKG_IOBJ:  // Integer
            next_quad( );
            break;
        case PKG_PAIR:  // Pair
            pair = wasp_pair_fv( wasp_vector_get( values, record_ix ) );
            wasp_set_car( pair, vf_word( next_word() ) );
            wasp_set_cdr( pair, vf_word( next_word() ) );
            break;
        case PKG_PROC: // Procedure
            // Vicious, dirty.. We assume the procedure is probably much
            // longer than it is..
            ; // For some reason, GCC bails if this isn't here..
            wasp_procedure proc = wasp_procedure_fv( 
                wasp_vector_get( values, record_ix )
            );
            ix = 0; ln = next_word() + memix;  
            while( memix < ln ){
                wasp_byte op = next_byte();
                if( op > wasp_max_opcode )err( "invalid opcode" );
                wasp_primitive prim = wasp_instr_table[ op ];
                proc->inst[ix].prim = prim; 

                if( prim->a ){
                    proc->inst[ix].a = vf_word( next_word() );
                };
                if( prim->b ){
                    proc->inst[ix].b = vf_word( next_word() );
                };

                ix++;
            };
            proc->length = ix; // Ugly like a stomach pump..
            break;
        case PKG_LIST: // List
            pair = wasp_pair_fv( wasp_vector_get( values, record_ix ) );
            ln = next_word();
            while( ln ){
                ln --;

                if( ln ){ 
                    next = wasp_cons( wasp_vf_null(), wasp_vf_null() );
                }else{ 
                    next = NULL;
                };

                wasp_set_car( pair, vf_word( next_word() ) );
                wasp_set_cdr( pair, wasp_vf_list( next ) );

                pair = next;
            }
            break;
        case PKG_STR: // String
            next_block( next_word( ) );
            break;
        case PKG_SYM: // Symbol
            next_block( next_word( ) );
            break;
        default:
            err( "bad record type" );
        }
        record_ix ++;
    }

    wasp_value result = wasp_vector_get( values, 0 );
    return result;
}

void wasp_freeze_ii( wasp_string buf, wasp_word x ){
    wasp_string_append_word( buf, x | 0x8000 );
}
void wasp_freeze_val( wasp_tree index, wasp_string buf, wasp_value v ){
    if( wasp_is_null( v ) ){
        return wasp_string_append_word( buf, 0x7FFF );
    }else if( wasp_is_true( v ) ){
        return wasp_string_append_word( buf, 0x7FFC );
    }else if( wasp_is_false( v ) ){
        return wasp_string_append_word( buf, 0x7FFD );
    }else if( wasp_is_integer( v ) ){
        int x = wasp_integer_fv( v );
        if(( x >= 0 ) && ( x < 0x8000 )){
            return wasp_freeze_ii( buf, x );
        }
    };
   
    wasp_node n = wasp_tree_lookup( index, v );
    
    wasp_string_append_word( buf, wasp_integer_fv( 
        wasp_cdr( wasp_pair_fv( n->data ) )
    ) );
}

wasp_string wasp_freeze( wasp_value root ){
    wasp_integer item_ct = 0;
    wasp_dict      index = wasp_make_dict( );
    wasp_pair      items = wasp_make_tc( );

    wasp_boolean inlineq( wasp_value value ){
        if( wasp_is_integer( value ) ){
            wasp_integer x = wasp_integer_fv( value );
            return ( x >= 0 ) && ( x < 0x8000 );
        }else return wasp_is_boolean( value ) ||
                     wasp_is_null( value );
    }
    
    void dissect( wasp_value value ){
        // We have already found this value.
        if( inlineq( value ) )return;
        if( wasp_tree_lookup( index, value ) )return;
        
        wasp_tree_insert( index, 
                         wasp_vf_pair( 
                            wasp_cons( value, wasp_vf_integer( item_ct ) ) ) );
        wasp_tc_append( items, value );
        item_ct ++;

        if( wasp_is_pair( value ) ){
            // Add the car and cdr as work.
            // NOTE: We should analyze this for list compression..
            wasp_pair pair = wasp_pair_fv( value );
            dissect( wasp_car( pair ) );
            dissect( wasp_cdr( pair ) );
        }else if( wasp_is_string( value ) ){
            // Do nothing -- strings do not contain references.
        }else if( wasp_is_symbol( value ) ){
            // Do nothing -- symbols do not contain references.
        }else if( wasp_is_integer( value ) ){
            //Do nothing -- integers do not contain references.
        }else if( wasp_is_procedure( value ) ){
            // Hoo boy. Here we go..
            wasp_procedure proc = wasp_procedure_fv( value );
            wasp_integer i, l = proc->length;
            for( i = 0; i < l; i ++ ){
                dissect( proc->inst[i].a );
                dissect( proc->inst[i].b );
            }
        }else{
            wasp_errf( wasp_es_pkg, "sx", "cannot package value", value );
        }
    }

    dissect( root );
    
    wasp_string pkg = wasp_make_string( 1024 );
    int i;
    wasp_value item;

    items = wasp_list_fv( wasp_car( items ) );

    if( inlineq( root ) ){ 
        wasp_freeze_val( index, pkg, root ); 
    }else{
        wasp_string_append_word( pkg, item_ct );

        for( i = 0; i < item_ct; i ++ ){
            item = wasp_car( items );
            items = wasp_list_fv( wasp_cdr( items ) );
            if( wasp_is_integer( item ) ){
                wasp_string_append_byte( pkg, PKG_IOBJ );
                wasp_string_append_quad( pkg, wasp_integer_fv( item ) );
            }else if( wasp_is_pair( item ) ){
                //TODO: Detect Lists.
                wasp_string_append_byte( pkg, PKG_PAIR );
                wasp_freeze_val( index, pkg, wasp_car( wasp_pair_fv( item ) ) );
                wasp_freeze_val( index, pkg, wasp_cdr( wasp_pair_fv( item ) ) );
            }else if( wasp_is_procedure( item ) ){ 
                wasp_procedure proc = wasp_procedure_fv( item );
                wasp_string field = wasp_make_string( 1024 );
                int j, m = proc->length;
                for( j = 0; j < m; j ++ ){
                    wasp_primitive prim = proc->inst[j].prim;
                    wasp_string_append_byte( field, prim->code );
                    if( prim->a ) wasp_freeze_val( index, field, proc->inst[j].a );
                    if( prim->b ) wasp_freeze_val( index, field, proc->inst[j].b );
                }
                wasp_string_append_byte( pkg, PKG_PROC );
                wasp_string_append_word( pkg, wasp_string_length( field ) );
                wasp_string_append( pkg, wasp_string_head( field ), 
                                       wasp_string_length( field ) );
            }else if( wasp_is_string( item ) ){
                wasp_string_append_byte( pkg, PKG_STR );
                wasp_string s = wasp_string_fv( item );
                wasp_string_append_word( pkg, wasp_string_length( s ) );
                wasp_string_append( pkg, 
                                  wasp_sf_string( s ), wasp_string_length( s ) );
            }else if( wasp_is_symbol( item ) ){
                wasp_string_append_byte( pkg, PKG_SYM );
                wasp_string s = wasp_symbol_fv( item )->string;
                wasp_string_append_word( pkg, wasp_string_length( s ) );
                wasp_string_append( pkg, 
                                  wasp_sf_string( s ), wasp_string_length( s ) );
            }
        }
    }

    return wasp_string_fm( wasp_string_head( pkg ),
                          wasp_string_length( pkg ) );
}

void wasp_init_package_subsystem(){
    wasp_es_pkg = wasp_symbol_fs( "pkg" );
}

#define REPORT_ERROR( s ){ error = "thaw: " s "."; goto yield; }
#define CHECK_UNDERFLOW( x, s ) if( len < ( ofs + (x) ) ) REPORT_ERROR( "data underflow while trying to read " s );
#define CHECK_REF( x, s ) if( ct <= (x) )REPORT_ERROR( "record " s " reference exceeds record count" );

/* Original inspiration for wasp_thaw_frag taken from public domain code
 * by Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
 */

const char* wasp_frag_tag = "wvf1";
const int wasp_frag_taglen = 4;

#include <stdio.h>
#include <string.h>
#include <errno.h>

#define cannot(x) \
    wasp_errf( \
        wasp_es_vm, "ss", "cannot " x " -- ", strerror(errno) \
    );

#define TAIL_JUMP( fil, ofs ) \
    *inset -= ofs; \
    if( fseek( fil, *inset, SEEK_END ) != 0 )cannot( "seek" );

#define TAIL_READ( fil, ptr, cnt ) \
    TAIL_JUMP( fil, cnt ); \
    if( fread( ptr, cnt, 1, fil ) != 1 )cannot( "read" ) 

#define TAIL_READ_VAR( fil, var ) \
    TAIL_READ( fil, &var, sizeof( var ) );

#define TAIL_READ_SHORT( fil, var ) \
    TAIL_READ_VAR( fil, var ); var = ntohs( var );

wasp_value wasp_thaw_frag( FILE *f, wasp_integer *inset ) {
    char* code;
    wasp_word code_len; 

    TAIL_READ_SHORT( f, code_len );
    //TODO: This should probably be illegal.
    if( code_len == 0 ) return 0;  
    code = malloc( code_len + 1 );
    
    TAIL_READ( f, code, code_len );
    code[code_len] = 0;

    wasp_value v = wasp_thaw_mem( code, code_len );
    
    free( code );
    return v;
}

wasp_pair wasp_thaw_tail( const char *name ) {
    char sig[wasp_frag_taglen];
    wasp_word i, count;
    wasp_integer iinset = 0;
    wasp_integer *inset = &iinset;
    wasp_pair p = NULL;
    // wasp_tc tc = wasp_make_tc( );
    wasp_value v;

    FILE *f = fopen( name, "rb" );

    if (f==NULL){
        cannot("open");
    };

    for(;;){
        TAIL_READ( f, sig, wasp_frag_taglen );
        if (memcmp(sig,wasp_frag_tag,wasp_frag_taglen)!=0) break;
        v = wasp_thaw_frag( f, inset );
        p = wasp_cons( v, wasp_vf_list( p ) ); 
        // wasp_tc_append( tc, v );
    }

    fclose(f);

    return p;
    // return wasp_list_fv( wasp_car( tc ) );
}

