/* Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
 * Portions from MOSVM's stream.c, Copyright (C) 2006 Ephemeral Security, 
 * LLC, used by permission via the LGPL.
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

#include <stdio.h>
#include <string.h>

#ifdef WASP_IN_WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wspiapi.h>

#else

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>

#endif

//TODO: Shutdown manifest for all services.

#ifdef WASP_DEBUG_IO
#define IO_TRACE printf
#else
#define IO_TRACE //
#endif

wasp_process wasp_os_loop_process;
unsigned int wasp_os_loop_use = 0;

void wasp_enable_os_loop( ){
    IO_TRACE( "OS Loop Enabled, Use Ct: %i\n", wasp_os_loop_use + 1 );
    if( wasp_os_loop_use ++ ) return;
    wasp_enable_process( wasp_os_loop_process );
}

void wasp_disable_os_loop( ){
    IO_TRACE( "OS Loop Disabled, Use Ct: %i\n", wasp_os_loop_use - 1 );
    if( -- wasp_os_loop_use ) return;
    wasp_disable_process( wasp_os_loop_process );
}

void wasp_activate_os_loop( ){ 
#ifdef WASP_IN_WIN32
    if( wasp_first_enabled == wasp_last_enabled ){
        SleepEx( 100, TRUE );
    }else{
        SleepEx( 0, TRUE );
    }
    event_loop( EVLOOP_NONBLOCK | EVLOOP_ONCE );
#else
    if( wasp_first_enabled == wasp_last_enabled ){
        event_loop( EVLOOP_ONCE );
    }else{
        event_loop( EVLOOP_NONBLOCK | EVLOOP_ONCE );
    }
#endif
    if( ! wasp_os_loop_process->enabled ) wasp_proc_loop( );
}
void wasp_deactivate_os_loop( ){ }

void wasp_os_start_writing( wasp_os_connection conn, wasp_string data ){
    char* str = wasp_sf_string( data );
    int   len = wasp_string_length( data );
    
    bufferevent_enable( conn->event, EV_WRITE );
    bufferevent_write( conn->event, str, len );
    //TODO: Try writing directly, first.. Sometimes it works!
    
    if( conn->writing ) return;
    IO_TRACE( "Started writing for connection %x\n", conn );
    conn->writing = 1;

    if( conn->reading )return;
    wasp_enable_os_loop( );
    wasp_root_obj( (wasp_object) conn );
}

void wasp_os_start_reading( wasp_os_connection conn ){
    if( conn->reading ) return;
    IO_TRACE( "Started reading for connection %x\n", conn );
    
    conn->reading = 1;
    bufferevent_enable( conn->event, EV_READ );

    if( conn->writing )return;
    wasp_enable_os_loop( );
    wasp_root_obj( (wasp_object) conn );
}

void wasp_os_stop_writing( wasp_os_connection conn ){
    if( ! conn->writing ) return;
    IO_TRACE( "Stopped writing for connection %x\n", conn );
    conn->writing = 0;
    bufferevent_disable( conn->event, EV_WRITE );

    if( conn->reading )return;
    wasp_disable_os_loop( );
    wasp_unroot_obj( (wasp_object) conn );
}

void wasp_os_stop_reading( wasp_os_connection conn ){
    if( ! conn->reading ) return;
    IO_TRACE( "Stopped reading for connection %x\n", conn );
    conn->reading = 0;
    bufferevent_disable( conn->event, EV_READ );

    if( conn->writing ) return;
    wasp_disable_os_loop( );
    wasp_unroot_obj( (wasp_object) conn );
}


void wasp_os_closed( wasp_os_connection conn ){    
    if( conn->state < WASP_CLOSED ){
        IO_TRACE( "OS Closed for connection %x\n", conn );
        
        close( conn->handle );
        conn->state = WASP_CLOSED;
        
        wasp_wake_monitor( 
            ((wasp_connection)conn)->input, wasp_vf_symbol( wasp_ss_close ) 
        );
        
        wasp_os_stop_writing( conn );
        wasp_os_stop_reading( conn );
    }
}

int wasp_os_xmit_complete( wasp_os_connection conn ){
    return ( ! EVBUFFER_LENGTH( EVBUFFER_OUTPUT( conn->event ) ) ); 
}

void wasp_os_close( wasp_os_connection conn ){
    if( conn->state < WASP_CLOSING ){
        IO_TRACE( "OS Closing for connection %x\n", conn );
        if( wasp_os_xmit_complete( conn ) ){
            wasp_os_closed( conn );
        }else{
            conn->state = WASP_CLOSING;
        }
    }
}

void wasp_os_xmit_mt( wasp_os_output outp, wasp_value data ){
    wasp_os_connection conn = outp->conn;
    
    if( wasp_is_symbol( data ) && wasp_ss_close == wasp_symbol_fv( data ) ){
        wasp_os_close( conn );
    }else if(  conn->state >= WASP_CLOSING ){
        // No transmissions are possible to a closed socket.
        wasp_errf( 
            wasp_es_vm, "sxx", "cannot transmit to closed outputs",
            outp, data 
        );
    }else if( wasp_is_string( data ) ){
        wasp_os_start_writing( conn, wasp_string_fv( data ) );
	}else{
        wasp_errf( 
            wasp_es_vm, "sxx", "OS outputs can only send strings", 
            outp, data 
        );
    }
}

wasp_string wasp_read_bufferevent( struct bufferevent* ev ){
    static char data[4096];
    int len = bufferevent_read( ev, data, sizeof( data ) );
    if( ! len ) return NULL;
    wasp_string str = wasp_string_fm( data, len );

    //TODO: There's an extra copy op, here.

    return str;
}

int wasp_os_recv_mt( wasp_os_input inp, wasp_value* data ){
    wasp_os_connection conn = inp->conn;
    
    if( conn->state >= WASP_CLOSING ){
        *data = wasp_vf_symbol( wasp_ss_close );
        return 1;
    }

    wasp_string str = wasp_read_bufferevent( inp->conn->event );  
    if( ! str ){
        wasp_os_start_reading( conn );
        return 0;
    }

    *data = wasp_vf_string( str );

    return 1;
}

void wasp_os_read_cb( 
    struct bufferevent* ev, wasp_os_connection conn 
){
    wasp_os_input input = (wasp_os_input)(((wasp_connection)conn)->input);
    if( ! wasp_input_monitored( (wasp_input) input ) ) return;
    wasp_string str = wasp_read_bufferevent( ev );  
    if( ! str ) return;
    wasp_os_stop_reading( conn );
    wasp_wake_monitor( (wasp_input)input, wasp_vf_string( str ) );
}

void wasp_os_xmit_cb( 
    struct bufferevent* ev, wasp_os_connection conn 
){
    IO_TRACE( "Detected write completion for %x\n", conn );
    if( conn->state == WASP_CLOSING ) wasp_os_closed( conn );
    wasp_os_stop_writing( conn );
    //TODO: Write completion notification.
}

void wasp_os_error_cb( 
    struct bufferevent* ev, short what, wasp_os_connection conn 
){
    wasp_os_closed( conn );
    IO_TRACE( "OS Error on %i: %i\n", conn->handle, what );
    //TODO: Probably need to store a symbol describing the real error..
}

int wasp_svc_recv_mt( wasp_os_service svc, wasp_value* data ){
    if( svc->closed ){
        *data = wasp_vf_symbol( wasp_ss_close );
        return 1;
    }else{
        wasp_enable_os_loop( );
        event_add( &( svc->event ), svc->timeout ? &( svc->timeval ) : NULL );
        return 0;
    }
}

void wasp_svc_read_cb( int handle, short event, void* service ){
    struct sockaddr addr;
    int sz = sizeof( addr );
    int fd = accept( handle, &addr, &sz);
    if( fd == -1 ) return; //TODO: Close? Fail?
        //TODO: Close down the connection, and unroot it.
    wasp_os_connection conn = wasp_make_os_connection( fd );
    
    wasp_disable_os_loop( );
    wasp_wake_monitor( (wasp_input)service, wasp_vf_os_connection( conn ) );
}

wasp_os_service wasp_make_os_service( int handle ){
    wasp_os_service svc = WASP_OBJALLOC( os_service );
    ((wasp_input)svc)->recv = (wasp_input_mt)wasp_svc_recv_mt;
    
    svc->timeout = svc->closed = 0;
    svc->timeval.tv_sec = svc->timeval.tv_usec = 0;
    event_set( &( svc->event ), handle, EV_READ, wasp_svc_read_cb, (void*)svc );
    wasp_root_obj( (wasp_object) svc ); //TODO: Need unroot on close.

    return svc;
}

wasp_os_connection wasp_make_os_connection( int handle ){
    //TODO: Unblock the handle. Note that this will not work with pipes.

    wasp_os_connection oscon = WASP_OBJALLOC( os_connection );
    wasp_os_input osin = WASP_OBJALLOC( os_input );
    wasp_os_output osout = WASP_OBJALLOC( os_output );

    osin->conn = oscon;
    ((wasp_input)osin)->recv = (wasp_input_mt)wasp_os_recv_mt;
    ((wasp_output)osout)->xmit = (wasp_output_mt)wasp_os_xmit_mt;

    osout->conn = oscon;

    wasp_init_connection( (wasp_connection) oscon, 
                          (wasp_input) osin, 
                          (wasp_output) osout );

    oscon->handle = handle;
    oscon->event = bufferevent_new( handle, 
                                    (evbuffercb) wasp_os_read_cb, 
                                    (evbuffercb) wasp_os_xmit_cb, 
                                    (everrorcb) wasp_os_error_cb, 
                                    oscon);
    bufferevent_enable( oscon->event, EV_WRITE );
    wasp_root_obj( (wasp_object) oscon ); //TODO: Needs unroot on close.

    return oscon;
}

void wasp_report_net_error( ){
#ifdef WASP_IN_WIN32
    wasp_errf( wasp_es_vm, "s", strerror( WSAGetLastError() ) );
#else
    if( errno == EINPROGRESS )return;
    wasp_errf( wasp_es_vm, "s", strerror( errno ) );
#endif
}

char* utoa (char* buf, unsigned int n){
    int d;

    if( n == 0 ){ buf[0] = '0'; buf[1] = 0; return buf; };
    
    buf += 16;
    *buf = 0;

    while( n ){
        d = n % 10;
        n /= 10;

        *( --buf ) = 48 + d;
    };
    
    return buf;
}

wasp_os_connection wasp_tcp_connect( wasp_string host, wasp_value service ){
    int result;
    struct addrinfo hints;
    struct addrinfo* addr;
    char* service_str;

    if( wasp_is_string( service ) ){
        service_str = wasp_sf_string( wasp_string_fv( service ) );
    }else{ 
        char buf[ 17 ];
        service_str = utoa( buf, wasp_req_integer( service ) );
    }
    
    bzero( &hints, sizeof( struct addrinfo ) );

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    addr = NULL;

    result = getaddrinfo( wasp_sf_string( host ), service_str, &hints, &addr );

    if( result ){
        if( addr ) freeaddrinfo( addr );
        wasp_errf( wasp_es_vm, "sxx", gai_strerror( result ), host, service );
    }

    result = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );

    if( result == -1 ){
        freeaddrinfo( addr ); 
        wasp_report_net_error( );
    }

    if( connect( result, addr->ai_addr, (int) addr->ai_addrlen ) ){
        freeaddrinfo( addr ); 
        wasp_report_net_error( );
    }

    return wasp_make_os_connection( result );
}

wasp_input wasp_stdin;
wasp_output wasp_stdout;

#ifdef WASP_IN_WIN32

wasp_connection wasp_console;
HANDLE wasp_vm_thread;

HANDLE wasp_stdin_fd;
HANDLE wasp_stdin_more;
char   wasp_stdin_buf[ 1024 ];
DWORD  wasp_stdin_len;
wasp_process wasp_stdin_mon = NULL;

HANDLE wasp_stdout_fd;

void wasp_console_xmit_mt( wasp_output output, wasp_value data ){
    if( wasp_is_symbol( data ) && wasp_ss_close == wasp_symbol_fv( data ) ){
        wasp_errf( 
            wasp_es_vm, "s", "the win32 console cannot be closed"
        );
    }else if( wasp_is_string( data ) ){ 
        const char* str = wasp_sf_string( wasp_string_fv( data ) );
        int len = wasp_string_length( wasp_string_fv( data ) );
        DWORD sent;
        while( len > 0 ){
            WriteFile( wasp_stdout_fd, str, len, &sent, NULL );
            len -= sent; str += sent;
        }
    }else{
        wasp_errf( 
            wasp_es_vm, "sx", "can only send strings to console"
        );
    };
}

int wasp_console_recv_mt( wasp_input inp, wasp_value* data ){
    wasp_stdin_mon = wasp_active_process;
    
    //TODO:WIN32 console should handle this..
    wasp_root_obj( (wasp_object) wasp_stdin_mon ); 
    
    IO_TRACE( "Signaling STDIN to Resume..\n" );
    SetEvent( wasp_stdin_more );
    wasp_enable_os_loop( );
    return 0;
}

CALLBACK void wasp_stdin_apc( DWORD ignored ){
    //TODO: Note that this method can easily lose data, if the process has changed
    //      what it is monitoring.  (Not that it is possible from userland, mind you.)
 
    IO_TRACE( "Beginning STDIN Update..\n" );
    if( ! wasp_stdin_mon ) 
        wasp_errf( wasp_es_vm, "s", "STDIN APC arrived without consumer." );

    IO_TRACE( "Waking Montoring Process..\n" );
    wasp_wake_process( 
        wasp_stdin_mon, 
        wasp_vf_string( wasp_string_fm( wasp_stdin_buf, wasp_stdin_len ) )
    );

    IO_TRACE( "Disabling OS Loop..\n" );
    wasp_disable_os_loop( );
}

CALLBACK int wasp_stdin_loop( void* param ){
    for(;;){
        IO_TRACE( "STDIN Waiting for Signal..\n");
        WaitForSingleObject( wasp_stdin_more, INFINITE );
        IO_TRACE( "STDIN Reading from User..\n" );
        ReadFile( wasp_stdin_fd, wasp_stdin_buf, 1024, &wasp_stdin_len, NULL );
        IO_TRACE( "STDIN Queueing Update..\n" );
        QueueUserAPC( wasp_stdin_apc, wasp_vm_thread, 0 );
    };
}

wasp_connection wasp_make_console( ){
    if( wasp_console ) return wasp_console;

    wasp_stdin = WASP_OBJALLOC( input );
    wasp_stdout = WASP_OBJALLOC( output );
    wasp_console = wasp_make_connection( wasp_stdin, wasp_stdout );
    wasp_root_obj( (wasp_object) wasp_console );

    wasp_stdin->recv = (wasp_input_mt)wasp_console_recv_mt;
    wasp_stdout->xmit = (wasp_output_mt)wasp_console_xmit_mt;

    wasp_stdin_fd = GetStdHandle( STD_INPUT_HANDLE );
    wasp_stdout_fd = GetStdHandle( STD_OUTPUT_HANDLE );
        
    HANDLE process, thread;
        
    process = GetCurrentProcess( );
    thread = GetCurrentThread( );
        
    DuplicateHandle( 
        process, thread, process, & wasp_vm_thread, 0, 
        TRUE, DUPLICATE_SAME_ACCESS
    );
        
    wasp_stdin_more = CreateEvent( NULL, FALSE, FALSE, NULL );
    CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE) wasp_stdin_loop, 
                  NULL, 0, NULL );
    
    return wasp_console;
}

wasp_connection wasp_make_stdio( ){ return wasp_make_console( ); }

#else

wasp_connection wasp_make_stdio( ){
    // The problem: STDIN and STDOUT have different file descriptors.  We 
    // create a connection for each, then take the resulting input and
    // output and bind them into a new connection to represent the console.
    
    wasp_os_connection oc = wasp_make_os_connection( STDOUT_FILENO );
    wasp_os_connection ic = wasp_make_os_connection( STDIN_FILENO );

    wasp_connection conn = wasp_make_connection( NULL, NULL );

    wasp_stdin = ((wasp_connection)ic)->input;
    wasp_stdout = ((wasp_connection)oc)->output;
    
    wasp_root_obj( (wasp_object) wasp_stdin ); 
    wasp_root_obj( (wasp_object) wasp_stdout ); 

    conn->input = wasp_stdin;
    conn->output = wasp_stdout;

    return conn;
}
#endif

wasp_free_os_connection( wasp_os_connection oscon ){ 
    bufferevent_free( oscon->event );
    wasp_objfree( oscon );
}

void wasp_trace_os_connection( wasp_os_connection oscon ){ 
    wasp_trace_connection( (wasp_connection) oscon );
}

WASP_GENERIC_FORMAT( os_connection )
WASP_GENERIC_COMPARE( os_connection )

WASP_C_SUBTYPE2( os_connection, "os-connection", connection );

void wasp_free_os_service( wasp_os_service svc ){ 
    event_del( &(svc->event) ); 
    wasp_objfree( (wasp_object)svc );
}

void wasp_trace_os_service( wasp_os_service svc ){
    wasp_trace_input( (wasp_input)svc );
}
WASP_GENERIC_FORMAT( os_service )
WASP_GENERIC_COMPARE( os_service )

WASP_C_SUBTYPE2( os_service, "os-service", input );

void wasp_trace_os_output( wasp_os_output output ){ 
    wasp_grey_obj( (wasp_object) output->conn );
}

void wasp_free_os_output( wasp_os_output output ){
    wasp_objfree( (wasp_object)output );
}

WASP_GENERIC_FORMAT( os_output )
WASP_GENERIC_COMPARE( os_output )

WASP_C_SUBTYPE2( os_input, "os-input", input );

void wasp_trace_os_input( wasp_os_input input ){ 
    wasp_grey_obj( (wasp_object) input->conn );
    wasp_trace_input( (wasp_input) input ); 
}
void wasp_free_os_input( wasp_os_input input ){
    wasp_objfree( (wasp_object)input );
}

WASP_GENERIC_FORMAT( os_input )
WASP_GENERIC_COMPARE( os_input )

WASP_C_SUBTYPE2( os_output, "os-output", output );

WASP_BEGIN_PRIM( "tcp-connect", tcp_connect )
    REQ_STRING_ARG( host );
    REQ_ANY_ARG( service );
    NO_REST_ARGS( );

    RESULT( wasp_vf_os_connection( wasp_tcp_connect( host, service ) ) );
WASP_END_PRIM( tcp_connect )

WASP_BEGIN_PRIM( "os-connection-input", os_connection_input )
    REQ_OS_CONNECTION_ARG( connection );
    NO_REST_ARGS( );

    RESULT( wasp_vf_input( connection->connection.input ) );
WASP_END_PRIM( os_connection_input );

WASP_BEGIN_PRIM( "os-connection-output", os_connection_output )
    REQ_OS_CONNECTION_ARG( connection );
    NO_REST_ARGS( );

    RESULT( wasp_vf_output( connection->connection.output ) );
WASP_END_PRIM( os_connection_output );

//TODO: This should be more generic..
wasp_integer wasp_net_error( wasp_integer k ){
    if( k == -1 )wasp_report_net_error( );
    return k;
}

WASP_BEGIN_PRIM( "serve-tcp", serve_tcp )
    REQ_INTEGER_ARG( portno );
    NO_REST_ARGS( );

    static struct sockaddr_in addr;

    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( INADDR_ANY );
    addr.sin_port = htons( portno );

    int server_fd = wasp_net_error( socket( AF_INET, SOCK_STREAM,
                                           IPPROTO_TCP ) );
    wasp_net_error( bind( server_fd, (struct sockaddr*)&addr, sizeof( addr ) ) );
    wasp_net_error( listen( server_fd, 5 ) );

#if defined( _WIN32 )||defined( __CYGWIN__ )
	//TODO:WIN32:IO Probably doesn't work on nonsockets.
    unsigned long unblocking = 1;
    wasp_net_error( ioctlsocket( server_fd, FIONBIO, &unblocking ) );
#else
    // wasp_net_error( fcntl( server_fd, F_SETFL, O_NONBLOCK ) );
    unsigned long unblocking = 1;
    wasp_net_error( ioctl( server_fd, FIONBIO, &unblocking ) );
#endif

    OS_SERVICE_RESULT( wasp_make_os_service( server_fd ) );
WASP_END_PRIM( serve_tcp )

//TODO: UDP Server
//TODO: UDP Connect
//TODO: EvDNS Wrapper

void wasp_init_os_subsystem( ){
#ifdef WASP_IN_WIN32
    WSADATA wsa_data;
    WSAStartup( 0x0202, &wsa_data );
#endif

#ifdef WASP_IN_DARWIN 
    //NOTE: On Darwin, these two methods fail to properly read STDIO; we 
    //      disable them, forcing LibEvent to use plain old select(2).

    setenv( "EVENT_NOKQUEUE", "yes", 1 );
    setenv( "EVENT_NOPOLL", "yes", 1 );
#endif
    event_init( );

    wasp_process p = wasp_make_process( wasp_activate_os_loop, 
                                        wasp_deactivate_os_loop, 
                                        wasp_vf_null( ) );
    wasp_root_obj( (wasp_object) p );
    wasp_os_loop_process = p;

    WASP_I_SUBTYPE( os_connection, connection );
    WASP_I_SUBTYPE( os_service, input );
    WASP_I_SUBTYPE( os_input, input );
    WASP_I_SUBTYPE( os_output, output );
    
    WASP_BIND_PRIM( tcp_connect );

    WASP_BIND_PRIM( os_connection_input );
    WASP_BIND_PRIM( os_connection_output );

    WASP_BIND_PRIM( serve_tcp );

    wasp_set_global( wasp_symbol_fs( "*console*" ), 
                     wasp_vf_connection( wasp_make_stdio( ) ) );
}
