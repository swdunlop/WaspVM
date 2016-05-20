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
#ifdef WASP_IN_WIN32
extern unsigned int wasp_active_apc;

int wasp_scan_argv_length( wasp_list arglist ){
    wasp_list list = arglist;
    int len = 0;

    while( list ){
        if( ! wasp_is_string( wasp_car( list ) ) ){
            wasp_errf( wasp_es_vm, "sx", "expected list of strings", arglist );
        };
        len += wasp_string_length( wasp_string_fv (wasp_car( list ) ) );
        if( ! wasp_is_pair( wasp_cdr( list ) ) )break;
        list = wasp_list_fv( wasp_cdr( list ) );
    }

    return len;
}

char* wasp_make_cmdline( wasp_list arglist, int ct, int len ){
    char* s = (char*) malloc( ( len + ct + 1 ) * sizeof( char* ) );
    char* p = s;
    wasp_list list = arglist;

    while( list ){
        wasp_string ss = wasp_string_fv( wasp_car( list ) );
        wasp_quad len = wasp_string_length( ss );
        strncpy( p, wasp_sf_string( ss ), len);
        p += len;
        if( wasp_list_fv( wasp_cdr( list ) )  ){
          *p++ = ' ';
        }
        list = wasp_list_fv( wasp_cdr( list ) );
    }
    *p = '\0';

    return s;
}

/* Based on code from:
   https://msdn.microsoft.com/en-us/library/windows/desktop/ms682499%28v=vs.85%29.aspx
   http://support.microsoft.com/kb/190351
*/
#include <fcntl.h>
int wasp_spawn_recv_mt( wasp_input inp, wasp_value* data ){
    wasp_win32_pipe_input i = (wasp_win32_pipe_input)inp;
    wasp_win32_pipe_connection conn = i->conn;

    if( conn->state >= WASP_CLOSING ){
        *data = wasp_vf_symbol( wasp_ss_close );
        return 1;
    }

    SetEvent( i->hEvent );
    /* While there is an active pipe going we need to prevent
       the os_loop process from blocking with EVLOOP_ONCE. If it
       blocks then the windows APC calls don't get processed. By
       manually increasing the active apc_count we tell that process
       that this process is waiting for an APC. It is decremented in
       the APC call.
    */
    wasp_active_apc++;

    wasp_enable_os_loop( );
    return 0;
}

void wasp_close_pipes ( wasp_win32_pipe_connection conn ){
    if( conn->state < WASP_CLOSING ) {
        wasp_win32_pipe_input inp = (wasp_win32_pipe_input)((wasp_connection)conn)->input;
        wasp_win32_pipe_output outp = (wasp_win32_pipe_output)((wasp_connection)conn)->output;

        CloseHandle( outp->hHandle );
        CloseHandle( inp->hHandle );
        CloseHandle( inp->hEvent );
        CloseHandle( inp->hThread );
        inp->hThread = NULL;
        inp->hEvent = NULL;
        inp->hHandle = NULL;
        outp->hHandle = NULL;

        conn->state = WASP_CLOSED;

        wasp_wake_monitor((wasp_input)inp, wasp_vf_symbol( wasp_ss_close ) );
    }
}

void wasp_spawn_xmit_mt( wasp_win32_pipe_output output, wasp_value data ){
    wasp_win32_pipe_connection conn = output->conn;

    if(  conn->state >= WASP_CLOSING ){
        wasp_errf(
            wasp_es_vm, "sxx", "cannot transmit to closed outputs",
            output, data
        );
    }else if( wasp_is_symbol( data ) && wasp_ss_close == wasp_symbol_fv( data ) ){
        wasp_close_pipes( conn );
    }else if( wasp_is_string( data ) ){
        const char* str = wasp_sf_string( wasp_string_fv( data ) );
        int len = wasp_string_length( wasp_string_fv( data ) );

        DWORD sent;
        while( len > 0 ){
            if( !WriteFile(output->hHandle, str, len, &sent, NULL ) ) {
                wasp_close_pipes( conn );
                break;
            }
            len -= sent; str += sent;
        }
        FlushFileBuffers( output->hHandle );
    }else{
        wasp_errf(
            wasp_es_vm, "sx", "can only send strings to pipes"
        );
    };
}

CALLBACK void wasp_spawn_apc( DWORD param ){
    wasp_win32_pipe_input i = (wasp_win32_pipe_input) param;
    if( i->buffer_len > 0 ){
        wasp_wake_monitor(
            (wasp_input)i,
            wasp_vf_string( wasp_string_fm( i->buffer, i->buffer_len ) )
        );
    }else{
        wasp_close_pipes( i->conn );
    }
    wasp_active_apc--;
    wasp_disable_os_loop( );
}

CALLBACK int wasp_spawn_stdin_loop( void* param ){
    wasp_win32_pipe_input i = (wasp_win32_pipe_input) param;
    for(;;){
        WaitForSingleObject( i->hEvent, INFINITE );
        if( !ReadFile( i->hHandle, i->buffer, 1024, &i->buffer_len, NULL ) ){
          i->buffer_len = 0;
        }
        QueueUserAPC( wasp_spawn_apc, i->hThread, (DWORD)param );
        if( i->buffer_len == 0 ){
            break;
        }
    };
}


wasp_connection wasp_spawn_cmd( wasp_string path, wasp_list arg, wasp_list var ){
    arg = wasp_cons( wasp_vf_string( path ), wasp_vf_list( arg ) );
    int argc = wasp_scan_argv( arg );
    int argl = wasp_scan_argv_length( arg );
    int varc = wasp_scan_argv( var );

    char* args = wasp_make_cmdline( arg, argc, argl );
    SECURITY_ATTRIBUTES sa;
    ZeroMemory( &sa, sizeof( sa ) );
    sa.nLength = sizeof( sa );
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    evutil_socketpair;
    /* stdout */
    HANDLE hChildStdOutRd;
    HANDLE hChildStdOutWr;
    if( !CreatePipe( &hChildStdOutRd, &hChildStdOutWr, &sa, 0 ) ){
        wasp_os_error( 0 );
    }

    if( !SetHandleInformation( hChildStdOutRd, HANDLE_FLAG_INHERIT, 0 ) ){
        wasp_os_error( 0 );
    }

    /* stdin */
    HANDLE hChildStdInRd;
    HANDLE hChildStdInWr;
    if( !CreatePipe( &hChildStdInRd, &hChildStdInWr, &sa, 0 ) ){
        wasp_os_error( 0 );
    }

    if( !SetHandleInformation( hChildStdInWr, HANDLE_FLAG_INHERIT, 0 ) ){
        wasp_os_error( 0 );
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(STARTUPINFO) );
    si.cb = sizeof( STARTUPINFO );
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hChildStdOutWr;
    si.hStdInput = hChildStdInRd;
    si.hStdError = hChildStdOutWr;
    si.wShowWindow = SW_HIDE;

    if ( !CreateProcess( NULL, /* lpApplicationName */
                         args, /* lpCommandLine */
                         NULL, /* lpProcessAttributes */
                         NULL, /* lpThreadAttributes */
                         TRUE, /* bInheritHandles */
                         CREATE_NEW_CONSOLE, /* dwCreationFlags */
                         NULL, /* lpEnvironment */
                         NULL, /* lpCurrentDirectory */
                         &si, /* lpStartupInfo */
                         &pi /* lpProcessInformation */ ) ){
        free( args );
        wasp_os_error( 0 );
    }else{
        free( args );
        CloseHandle( pi.hProcess );
        CloseHandle( pi.hThread );
        CloseHandle( hChildStdOutWr );
        CloseHandle( hChildStdInRd );
        wasp_win32_pipe_input conn_stdin = WASP_OBJALLOC( win32_pipe_input );
        wasp_win32_pipe_output conn_stdout = WASP_OBJALLOC( win32_pipe_output );
        wasp_win32_pipe_connection conn = WASP_OBJALLOC( win32_pipe_connection );
        wasp_init_connection( (wasp_connection) conn, (wasp_input) conn_stdin, (wasp_output) conn_stdout );
        conn->state = WASP_CONNECTED;
        conn_stdout->conn = conn;
        conn_stdin->conn = conn;

        ((wasp_input)conn_stdin)->recv = (wasp_input_mt)wasp_spawn_recv_mt;
        ((wasp_output)conn_stdout)->xmit = (wasp_output_mt)wasp_spawn_xmit_mt;

        conn_stdin->hHandle = hChildStdOutRd;
        conn_stdout->hHandle = hChildStdInWr;

        HANDLE process = GetCurrentProcess();
        HANDLE thread = GetCurrentThread();
        DuplicateHandle(
          process, thread, process, & conn_stdin->hThread, 0,
          TRUE, DUPLICATE_SAME_ACCESS
        );
        conn_stdin->hEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
        CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE) wasp_spawn_stdin_loop,
                      conn_stdin, 0, NULL );
        return (wasp_connection) conn;
    }
}
#else
#include <sys/socket.h>
wasp_connection wasp_spawn_cmd( wasp_string path, wasp_list arg, wasp_list var ){
    int argc = wasp_scan_argv( arg );
    int varc = wasp_scan_argv( var );

    int fds[2];

    arg = wasp_cons( wasp_vf_string( path ), wasp_vf_list( arg ) );

    wasp_os_error( socketpair( AF_LOCAL, SOCK_STREAM, 0, fds ) ); 

    char** argv = wasp_make_argv( arg, argc + 1);
    char** varv = varc ? wasp_make_argv( var, varc ) : environ;

    wasp_connection conn = (wasp_connection)wasp_make_os_connection( fds[0], 1 );

    int pid = fork(); 

    if( pid ){
        free( argv );
        if( varc )free( varv );
        wasp_os_error( pid );
        close( fds[1] );
        return conn;
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
#endif

WASP_BEGIN_PRIM( "spawn-command", spawn_command );
    REQ_STRING_ARG( path );
    OPT_LIST_ARG( args );
    OPT_LIST_ARG( env );
    NO_REST_ARGS( );
    
    CONNECTION_RESULT( wasp_spawn_cmd( path, args, env ) );
WASP_END_PRIM( spawn_command );

wasp_list wasp_get_environ( ){
    char** env = environ;
    wasp_tc tc = wasp_make_tc( );
    while( *env ){
        wasp_tc_add( tc, wasp_vf_string( wasp_string_fs( *env ) ) );
        env++;
    }
    return tc->head;
};

WASP_BEGIN_PRIM( "run-command", run_command );
    REQ_STRING_ARG( command );
    NO_REST_ARGS( );
    
    INTEGER_RESULT( wasp_os_error( system( wasp_sf_string( command ) ) ) );
WASP_END_PRIM( spawn_command );

void wasp_init_shell_subsystem( ){

    WASP_BIND_PRIM( spawn_command );

    wasp_set_global( wasp_symbol_fs( "*environ*" ), 
                     wasp_vf_list( wasp_get_environ( ) ) );
    WASP_BIND_PRIM( run_command );
}
