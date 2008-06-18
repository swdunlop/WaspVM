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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include "waspvm.h"


//TODO: This will not work on win32.
extern char** environ;

int wasp_scan_argv( wasp_list arglist ){
    wasp_list list = arglist;
    int ct = 0;

    while( list ){
        ct ++;
        if( ! wasp_is_string( wasp_car( list ) ) ){
            wasp_errf( wasp_es_vm, "sx", "expected list of strings", arglist );
        };
        if( ! wasp_is_pair( wasp_cdr( list ) ) )break;
        list = wasp_list_fv( wasp_cdr( list ) );
    }

    return ct;
}
char** wasp_make_argv( wasp_list arglist, int ct ){
    char** argv = (char**) malloc( ( ct + 1 ) * sizeof( char* ) );
    wasp_list list = arglist;
    ct = 0;

    while( list ){
        argv[ct++] = wasp_sf_string( wasp_string_fv( wasp_car( list ) ) );
        list = wasp_list_fv( wasp_cdr( list ) );
    }
    
    argv[ct] = NULL;

    return argv;
}
#ifdef TODO_MUST_RESTORE
#include <sys/socket.h>
// spawn_cmd not defined for win32, yet.
wasp_stream wasp_spawn_cmd( wasp_string path, wasp_list arg, wasp_list var ){
    int argc = wasp_scan_argv( arg );
    int varc = wasp_scan_argv( var );

    int fds[2];

    arg = wasp_cons( wasp_vf_string( path ), wasp_vf_list( arg ) );

    wasp_os_error( socketpair( AF_LOCAL, SOCK_STREAM, 0, fds ) ); 

    char** argv = wasp_make_argv( arg, argc );
    char** varv = varc ? wasp_make_argv( var, varc ) : environ;

    int pid = fork(); 

    if( pid ){
        free( argv );
        if( varc )free( varv );
        wasp_os_error( pid );
        close( fds[1] );
        return wasp_make_stream( fds[0] );
    }else{
        close( fds[0] );
        // Awww yeah.. Duping and forking like it's 1986..
        dup2( fds[1], STDIN_FILENO );
        dup2( fds[1], STDOUT_FILENO );
        
        execve( wasp_sf_string( path ), argv, varv );
        // We shouldn't be here, but here we are..
        close( fds[1] );
        _exit(0);
    }
}

WASP_BEGIN_PRIM( "spawn-command", spawn_command );
    REQ_STRING_ARG( path );
    OPT_LIST_ARG( args );
    OPT_LIST_ARG( env );
    NO_REST_ARGS( );
    
    STREAM_RESULT( wasp_spawn_cmd( path, args, env ) );
WASP_END_PRIM( spawn_command );
#endif

WASP_BEGIN_PRIM( "run-command", run_command );
    REQ_STRING_ARG( command );
    NO_REST_ARGS( );
    
    INTEGER_RESULT( wasp_os_error( system( wasp_sf_string( command ) ) ) );
WASP_END_PRIM( spawn_command );

void wasp_init_shell_subsystem( ){
#ifdef TODO_MUST_RESTORE
// spawn_cmd not defined for win32, yet.
    WASP_BIND_PRIM( spawn_command );
#endif

    WASP_BIND_PRIM( run_command );
    char** env = environ;
    wasp_tc tc = wasp_make_tc( );
    while( *env ){
        wasp_tc_add( tc, wasp_vf_string( wasp_string_fs( *env ) ) );
        env++;
    }
    wasp_set_global( wasp_symbol_fs( "*environ*" ), wasp_car( tc ) );
}
