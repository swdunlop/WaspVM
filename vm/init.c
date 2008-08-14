/* Copyright (C) 2006, Scott W. Dunlop
 * Portions Copyright (C) 2006, Ephemeral Security, LLC
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

#ifndef NDEBUG
// All praise the BSD malloc..
// char* malloc_options = "ADFG";
#endif

int wasp_show_globals = 0;
int wasp_argc;
wasp_list wasp_argv;

wasp_symbol wasp_ss_main;

void wasp_init_core_subsystems( ){
    wasp_init_memory_subsystem( );
    wasp_init_string_subsystem( );
    wasp_init_boolean_subsystem( );
    wasp_init_number_subsystem( );
    wasp_init_list_subsystem( );
    wasp_init_tree_subsystem( );
    wasp_init_vector_subsystem( );
    wasp_init_procedure_subsystem( );
    wasp_init_primitive_subsystem( );
    wasp_init_closure_subsystem( );
    wasp_init_vm_subsystem( );
    wasp_init_error_subsystem( );
    wasp_init_package_subsystem( );
    wasp_init_print_subsystem( );
    wasp_init_process_subsystem( );
    wasp_init_channel_subsystem( );
    wasp_init_parse_subsystem( );
    wasp_init_tag_subsystem( );
    wasp_init_multimethod_subsystem( );
    // wasp_init_plugin_subsystem( ); Disabled until after 1.0.
    wasp_init_file_subsystem( );
    wasp_init_channel_subsystem( );
    wasp_init_connection_subsystem( );
    wasp_init_queue_subsystem( );
    wasp_init_shell_subsystem( );
    wasp_init_os_subsystem( );
    wasp_init_time_subsystem( );

    wasp_init_regex_subsystem( );
    wasp_init_filesystem_subsystem( );
    wasp_init_crc32_subsystem( );

    wasp_init_curve25519_subsystem( );
    wasp_init_salsa20_subsystem( );

    wasp_ss_main = wasp_symbol_fs( "main" );

    wasp_bind_core_prims( );
}

void wasp_init_waspvm( int argc, const char* argv[] ){
    wasp_init_core_subsystems( );

    wasp_tc tc = wasp_make_tc( );
    wasp_argc = 0;
    int i;

    for( i = 0; i < argc; i ++ ){
        if( ! strcmp( argv[i], "-d" ) ){
            WASP_T ++;
        }else if( ! strcmp( argv[i], "-x" ) ){
            wasp_abort_on_error = 1;
        }else if( ! strcmp( argv[i], "-g" ) ){
            wasp_show_globals = 1;
        }else{
            wasp_tc_add( tc, wasp_vf_string( wasp_string_fs( argv[i] ) ) );
            wasp_argc ++;
        }
    };

    wasp_argv = tc->head;
    wasp_root_obj( (wasp_object) wasp_argv );
}

#include "waspvm.h"
#include <string.h>

#ifdef WASP_IN_WIN32
#include <windows.h>
#else
#include <signal.h>

//TODO: Add (disable-sigint) so the drone can block this.
void wasp_handle_sigint( int sig ){
    wasp_string s = wasp_make_string( 128 );
    wasp_string_append_newline( s );
    wasp_string_append_cs( s, "Interrupted by user." );
    wasp_string_append_newline( s );
    wasp_format_context( s, wasp_frame_context( WASP_CP ) );
    wasp_string_append_newline( s );
    wasp_printstr( s );
    exit(909);
}
#endif

void wasp_run( wasp_value func, wasp_list rest ){
    wasp_process p = wasp_spawn_call( wasp_cons( func, wasp_vf_list( rest ) ) );
    
    wasp_set_process_output( p, wasp_vf_output( (wasp_output) wasp_stdout ) );
    wasp_set_process_input( p, wasp_vf_input( (wasp_input) wasp_stdin ) );

    wasp_proc_loop( );
}

void wasp_run_main( ){
    if( wasp_has_global( wasp_ss_main ) ){
        wasp_run( wasp_get_global( wasp_ss_main ), wasp_argv );
    };
}

void wasp_load_linked( wasp_string prog_path ){
    wasp_pair linked = wasp_thaw_tail( wasp_sf_string( prog_path ) );
    wasp_root_value( linked );

    if( ! linked ){
        if( wasp_argv ){
            wasp_string src_path = wasp_string_fv( wasp_car( wasp_argv ) );
            wasp_file src_file = wasp_open_file( wasp_sf_string( src_path ),
                                               "r", 0600 );
            wasp_run( wasp_thaw_str( wasp_read_file( src_file, 1 << 30 ) ), NULL );
        }
    }else while( linked ){
        wasp_value next = wasp_car( linked );
        if( next ) wasp_run( next, NULL );
        linked = wasp_list_fv( wasp_cdr( linked ) );
    }
}

// Finds the program that provided the executing image.
wasp_string wasp_find_arg0( int argc, const char** argv ){
#ifdef WASP_IN_WIN32 
    char prog_path[256];
    GetModuleFileName( NULL, prog_path, sizeof(prog_path) );
#else
    const char* prog_path = argv[0];
#endif
    wasp_string wasp = wasp_string_fs( prog_path );

#ifndef WASP_IN_WIN32
    // PATH is a POSIX devil.. Windows is much better about telling us
    // where the image is.  How often can we say that??
    if( ! wasp_file_exists( wasp ) ) wasp = wasp_locate_util( wasp );
#endif    
    
    return wasp;
}

