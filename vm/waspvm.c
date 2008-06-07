/* Copyright (C) 2006, Scott W. Dunlop <swdunlop@gmail.com>
 *
 * Portions Copyright (C) 2006, Ephemeral Security, furnished via the LGPL.
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
#include <signal.h>

#ifdef WASP_IN_CYGWIN
#include <w32api/windows.h>
#endif

#ifdef WASP_IN_MINGW
#include <windows.h>
#endif

// This file describes the basic WaspVM bootstrap for the WaspVM stub binary;
// it will initialize the VM, load any linked modules -- see waspld -- and run
// the main program, if one has been supplied.

int main( int argc, const char** argv ){
    wasp_string wasp = wasp_find_arg0( argc, argv );
    wasp_init_waspvm( argc - 1, argv + 1 );

#ifndef WASP_IN_WIN32
    // We like sigint to trigger a trace and bail out.  Not the best behavior,
    // but it'll do for 1.0.
    signal( SIGINT, wasp_handle_sigint );

    // SIGPIPE is the devil; wasp's write operations check for errors.
    signal( SIGPIPE, SIG_IGN );
#endif
    
    wasp_load_linked( wasp );
    wasp_run_main( );

    if( wasp_show_globals ){
        wasp_list globals = wasp_get_globals( );
        while( globals ){
            wasp_show( wasp_car( wasp_pair_fv( wasp_car( globals ) ) ) );
            wasp_print( " -- " );
            wasp_show( wasp_value_type( wasp_cdr( wasp_pair_fv( wasp_car( globals ) ) ) )->name );
            wasp_newline( );
            globals = wasp_list_fv( wasp_cdr( globals ) );
        };
    };

    return 0;
}
