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
// disabled as per Chris Double's recommendation, 20110101
// #include <wspiapi.h>
#else

#include <unistd.h>
#include <termios.h>
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
unsigned int wasp_active_apc = 0;
wasp_symbol wasp_ss_connect;

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

void wasp_os_poll( ){
#ifdef WASP_IN_WIN32
        // This is a necessary workaround for Windows to process APC
        // events. It's important that wasp processes waiting for an APC
        // event don't allow the libevent event_loop here to block, otherwise
        // the APC won't get run. Those processes should increment
        // wasp_active_apc if it is waiting for an APC event and decrement
        // it when the event is run.
        SleepEx( 0, TRUE );
#endif
    if( wasp_active_apc == 0 && wasp_enable_count == 1 ){
        event_loop( EVLOOP_ONCE );
    }else{
        event_loop( EVLOOP_NONBLOCK | EVLOOP_ONCE ); 
    }
}

void wasp_enable_conn_loop( wasp_os_connection oscon ){
    if( oscon->looping ) return;
    oscon->looping = 1;
    wasp_enable_os_loop( );
    wasp_root_obj( (wasp_object) oscon );
}

void wasp_disable_conn_loop( wasp_os_connection oscon ){
    if( ! oscon->looping ) return;
    if( oscon->reading ) return;
    if( oscon->writing ) return;
    if( oscon->state == WASP_CONNECTING ) return;

    oscon->looping = 0;
    wasp_disable_os_loop( );
    wasp_unroot_obj( (wasp_object) oscon );
}

void wasp_os_start_writing( wasp_os_connection conn, wasp_string data ){
    char* str = wasp_sf_string( data );
    int   len = wasp_string_length( data );
    
    if( conn->writing ){
        bufferevent_write( conn->event, str, len );
    }else{
        conn->writing = 1;
        bufferevent_enable( conn->event, EV_WRITE );
        bufferevent_write( conn->event, str, len );
        wasp_enable_conn_loop( conn );
    }
    //TODO: Try writing directly, first.. Sometimes it works!
}

void wasp_os_start_reading( wasp_os_connection conn ){
    if( conn->reading ) return;
    conn->reading = 1;
    bufferevent_enable( conn->event, EV_READ );
    wasp_enable_conn_loop( conn );
}

void wasp_os_stop_writing( wasp_os_connection conn ){
    if( ! conn->writing ) return;
    conn->writing = 0;
    bufferevent_disable( conn->event, EV_WRITE );
    wasp_disable_conn_loop( conn );
}

void wasp_os_stop_reading( wasp_os_connection conn ){
    if( ! conn->reading ) return;
    conn->reading = 0;
    bufferevent_disable( conn->event, EV_READ );
    wasp_disable_conn_loop( conn );
}

void wasp_os_closed( wasp_os_connection conn ){    
    if( conn->state < WASP_CLOSED ){
        IO_TRACE( "OS Closed for connection %x\n", conn );
        
        close( conn->handle );
        conn->state = WASP_CLOSED;
          
        wasp_os_stop_writing( conn );
        wasp_os_stop_reading( conn );

        wasp_wake_monitor( 
            ((wasp_connection)conn)->input, wasp_vf_symbol( wasp_ss_close ) 
        );
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
            IO_TRACE( "Deferring closure, still got %i data on %x\n", EVBUFFER_LENGTH( EVBUFFER_OUTPUT( conn->event ) ), conn );
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

    if( conn->state < WASP_CONNECTED ) return 0;

    if( conn->conn_ready ){
        *data = wasp_vf_symbol( wasp_ss_connect );
        conn->conn_ready = 0; 
        wasp_disable_conn_loop( conn );
        return 1;
    };

    if( conn->state >= WASP_CLOSING ){
        if( conn->close_sent ){
            return 0; // This causes an eternal wait; close is only produced
                      // once.
        };
        conn->close_sent = 1;
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
    if( conn->state < WASP_CONNECTED ){
        conn->state = WASP_CONNECTED;
        wasp_input input = ((wasp_connection)conn)->input;

        if( ! wasp_wake_monitor( 
            input, wasp_vf_symbol( wasp_ss_connect )  
        ) ) conn->conn_ready = 1;
        
        wasp_disable_conn_loop( conn );
    };

    wasp_os_stop_writing( conn );
    if( conn->state == WASP_CLOSING ) wasp_os_closed( conn );
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
        wasp_root_obj( (wasp_object) svc );
        IO_TRACE( "-- %4i -- LISTENER -- ENABLE --\n", svc->handle );
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
    
    wasp_unroot_obj( (wasp_object) service );
    IO_TRACE( "-- %4i -- LISTENER -- DISABLE --\n",((wasp_os_service) service)->handle );
    wasp_disable_os_loop( );
    
    wasp_os_connection conn = wasp_make_os_connection( fd, 1 );
    
    wasp_wake_monitor( (wasp_input)service, wasp_vf_os_connection( conn ) );
}

wasp_os_service wasp_make_os_service( int handle ){
    wasp_os_service svc = WASP_OBJALLOC( os_service );
    ((wasp_input)svc)->recv = (wasp_input_mt)wasp_svc_recv_mt;
    svc->handle = handle; 
    svc->timeout = svc->closed = 0;
    svc->timeval.tv_sec = svc->timeval.tv_usec = 0;
    event_set( &( svc->event ), handle, EV_READ, wasp_svc_read_cb, (void*)svc );

    return svc;
}

void wasp_os_close_service( wasp_os_service service ){
    if( service->closed ) return;
    service->closed = 1;
    close( service->handle );
    event_del( &( service->event ) );

    if( wasp_input_monitored( (wasp_input) service ) ){
        IO_TRACE( "Alerting service monitor for %x.\n", service );
        wasp_unroot_obj( (wasp_object) service );
        IO_TRACE( "-- %4i -- L-SHUTDOWN -- DISABLE --\n", service->handle );
        wasp_disable_os_loop( ); 
        wasp_wake_monitor( 
            (wasp_input)service, wasp_vf_symbol( wasp_ss_close ) 
        );
    };
}

wasp_os_connection wasp_make_os_connection( int handle, int connected ){
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
    
    if( connected ){
        oscon->state = WASP_CONNECTED;
    }else{
        bufferevent_enable( oscon->event, EV_WRITE );
        oscon->state = WASP_CONNECTING;
        wasp_enable_conn_loop( oscon );
    }

    return oscon;
}

void wasp_report_host_error( ){
#if defined(_WIN32)||defined(__CYGWIN__)
    wasp_errf( wasp_es_vm, "s", strerror( WSAGetLastError() ) );
#else
    wasp_errf( wasp_es_vm, "s", hstrerror( h_errno ) );
#endif
}

void wasp_report_net_error( ){
#ifdef WASP_IN_WIN32
    wasp_errf( wasp_es_vm, "s", strerror( WSAGetLastError() ) );
#else
    if( errno == EINPROGRESS )return;
    wasp_errf( wasp_es_vm, "s", strerror( errno ) );
#endif
}

//TODO: This should be more generic..
wasp_integer wasp_net_error( wasp_integer k ){
    if( k == -1 )wasp_report_net_error( );
    return k;
}

void wasp_unblock_fd( int fd ){
#if defined( _WIN32 )||defined( __CYGWIN__ )
    //TODO:WIN32:IO Probably doesn't work on nonsockets.
    unsigned long unblocking = 1;
    wasp_net_error( ioctlsocket( fd, FIONBIO, &unblocking ) );
#else
    unsigned long unblocking = 1;
    wasp_net_error( ioctl( fd, FIONBIO, &unblocking ) );
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

wasp_os_connection wasp_tcp_connect( wasp_value host, wasp_value service ){
    int result;
    struct addrinfo hints;
    struct addrinfo* addr;
    char* service_str;
    wasp_string host_str;

    if( wasp_is_integer( host ) ){
        wasp_quad addr = wasp_integer_fv( host );
        host_str = wasp_formatf( "isisisi",
                                 addr >> 24, ".",
                                 (addr >> 16) & 255, ".",
                                 (addr >> 8) & 255, ".",
                                 addr & 255 );
    }else host_str = wasp_req_string( host ) ;

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

    result = getaddrinfo( 
        wasp_sf_string( host_str ), service_str, &hints, &addr 
    );

    if( result ){
        if( addr ) freeaddrinfo( addr );
        wasp_errf( wasp_es_vm, "sxx", gai_strerror( result ), host, service );
    }

    result = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );

    if( result == -1 ){
        freeaddrinfo( addr ); 
        wasp_report_net_error( );
    }
   
    //TODO: Enable after Wasp I/O Rewrite
    //wasp_unblock_fd( result );
    if( connect( result, addr->ai_addr, (int) addr->ai_addrlen ) ){
        freeaddrinfo( addr ); 
        wasp_report_net_error( );
    }
    //TODO: Disable after Wasp I/O Rewrite
    wasp_unblock_fd( result );
    
    wasp_os_connection conn = wasp_make_os_connection( result, 0 );
    IO_TRACE( "Connecting to remote host on %x\n", conn );

    return conn;
}

wasp_integer wasp_resolve_ipv4( wasp_string name ){
    struct hostent *entry = gethostbyname( wasp_sf_string( name ) );

    if( !entry ){
        wasp_report_host_error( );
    }else if( entry->h_length != 4 ){
        wasp_errf( wasp_es_vm, "sx", "expected an ipv4 address", name );
    }else{
        //TODO: A better version of resolve would return a list of
        //      addresses..
        return ntohl( *(wasp_integer*)(entry->h_addr) );
    }
}

WASP_BEGIN_PRIM( "resolve-ipv4", resolve_ipv4 )
    REQ_STRING_ARG( address )
    INTEGER_RESULT( wasp_resolve_ipv4( address ) );
WASP_END_PRIM( resolve_ipv4 )

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

WASP_BEGIN_PRIM( "conio-size", conio_size )
    NO_REST_ARGS( );
    
    CONSOLE_SCREEN_BUFFER_INFO info;
    if( ! GetConsoleScreenBufferInfo( wasp_stdout_fd, &info ) ){
        wasp_raise_winerror( wasp_es_vm );
    };

    LIST_RESULT( wasp_listf( 2, 
        // changed due to build issues with msys/mingw, 20110101
        // wasp_vf_integer( info.Y ), wasp_vf_integer( info.X )
        wasp_vf_integer( info.dwSize.Y ), 
        wasp_vf_integer( info.dwSize.X )
    ) );
WASP_END_PRIM( conio_size )

WASP_BEGIN_PRIM( "conio-goto", conio_goto )
    REQ_INTEGER_ARG( row )
    REQ_INTEGER_ARG( col )
    NO_REST_ARGS( );
    
    COORD pos = { col - 1, row - 1 };
    if( ! SetConsoleCursorPosition( wasp_stdout_fd, pos ) ){
        wasp_raise_winerror( wasp_es_vm );
    };

    NO_RESULT( );
WASP_END_PRIM( conio_goto )

WASP_BEGIN_PRIM( "conio-clear", conio_clear )
    NO_REST_ARGS( );
    
    CONSOLE_SCREEN_BUFFER_INFO info;
    if( ! GetConsoleScreenBufferInfo( wasp_stdout_fd, &info ) ){
        wasp_raise_winerror( wasp_es_vm );
    };
    
    int x = info.dwCursorPosition.X, y = info.dwCursorPosition.Y;
    int l = info.dwSize.X - x;

    FillConsoleOutputAttribute( 
        wasp_stdout_fd, info.wAttributes, l, info.dwCursorPosition, NULL 
    );
    FillConsoleOutputCharacter( 
        wasp_stdout_fd, ' ', l, info.dwCursorPosition, NULL 
    );

    NO_RESULT( );
WASP_END_PRIM( conio_clear )

WASP_BEGIN_PRIM( "conio-cls", conio_cls )
    NO_REST_ARGS( );
    
    CONSOLE_SCREEN_BUFFER_INFO info;
    if( ! GetConsoleScreenBufferInfo( wasp_stdout_fd, &info ) ){
        wasp_raise_winerror( wasp_es_vm );
    };
    
    int l = info.dwSize.X * info.dwSize.Y;
    COORD c = { 0, 0 };
    FillConsoleOutputAttribute( wasp_stdout_fd, info.wAttributes, l, c, NULL );
    FillConsoleOutputCharacter( wasp_stdout_fd, ' ', l, c, NULL );
    NO_RESULT( );
WASP_END_PRIM( conio_cls )

#else

wasp_connection wasp_make_stdio( ){
    // The problem: STDIN and STDOUT have different file descriptors.  We 
    // create a connection for each, then take the resulting input and
    // output and bind them into a new connection to represent the console.
    
    wasp_os_connection oc = wasp_make_os_connection( STDOUT_FILENO, 1 );
    wasp_os_connection ic = wasp_make_os_connection( STDIN_FILENO, 1 );

    wasp_connection conn = wasp_make_connection( NULL, NULL );

    wasp_stdin = ((wasp_connection)ic)->input;
    wasp_stdout = ((wasp_connection)oc)->output;
    
    wasp_root_obj( (wasp_object) wasp_stdin ); 
    wasp_root_obj( (wasp_object) wasp_stdout ); 

    conn->input = wasp_stdin;
    conn->output = wasp_stdout;

    IO_TRACE( "STDOUT is %x\n", oc );
    IO_TRACE( "STDIN is %x\n", ic );
    IO_TRACE( "STDIO is %x\n", conn );

    return conn;
}

WASP_BEGIN_PRIM( "tty-size", tty_size )
    REQ_ANY_ARG( tty );
    NO_REST_ARGS( );
    
    wasp_os_connection cn;
    if( wasp_is_os_connection( tty ) ){
        cn = wasp_os_connection_fv( tty );
    }else if( wasp_is_os_input( tty ) ){
        cn = wasp_os_input_fv( tty )->conn;
    }else if( wasp_is_os_output( tty ) ){
        cn = wasp_os_output_fv( tty )->conn;
    }else{
        wasp_errf( wasp_es_vm, "sx",
                  "expected OS connection, input or output", tty );
    };

// TODO: This is Linux-specific.
    struct winsize sz;
    wasp_os_error( ioctl( cn->handle, TIOCGWINSZ, &sz ) );

    LIST_RESULT( wasp_listf( 2, 
        wasp_vf_integer( sz.ws_row ), wasp_vf_integer( sz.ws_col ) 
    ) );
WASP_END_PRIM( tty_size )

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

WASP_BEGIN_PRIM( "start-tcp-connect", start_tcp_connect )
    REQ_ANY_ARG( host );
    REQ_ANY_ARG( service );
    NO_REST_ARGS( );

    RESULT( wasp_vf_os_connection( wasp_tcp_connect( host, service ) ) );
WASP_END_PRIM( start_tcp_connect )

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
    
    wasp_unblock_fd( server_fd );

    OS_SERVICE_RESULT( wasp_make_os_service( server_fd ) );
WASP_END_PRIM( serve_tcp )

WASP_BEGIN_PRIM( "close-service", close_service )
    REQ_OS_SERVICE_ARG( service );
    NO_REST_ARGS( );
    
    wasp_os_close_service( service );

    NO_RESULT( );
WASP_END_PRIM( close_service );
#ifdef WASP_IN_WIN32
void wasp_raise_winerror( wasp_symbol es ){
    char buffer[255];
    int err = GetLastError( );

    FormatMessage( 
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, 0, buffer, 255, NULL
    );
    
    wasp_errf( es, "si", buffer, err );
}
#endif

#ifdef WASP_IN_WIN32
/* win32_pipe_connection */
wasp_free_win32_pipe_connection( wasp_win32_pipe_connection conn ){
    wasp_objfree( conn );
}

void wasp_trace_win32_pipe_connection( wasp_win32_pipe_connection conn ){
    wasp_trace_connection( (wasp_connection) conn );
}

WASP_GENERIC_FORMAT( win32_pipe_connection )
WASP_GENERIC_COMPARE( win32_pipe_connection )
WASP_C_SUBTYPE2( win32_pipe_connection, "win32_pipe_connection", connection );

/* win32_pipe_input */
void wasp_free_win32_pipe_input( wasp_win32_pipe_input input ){
    wasp_objfree( (wasp_object) input );
}

void wasp_trace_win32_pipe_input( wasp_win32_pipe_input input ){
    wasp_grey_obj( (wasp_object) input->conn );
    wasp_trace_input( (wasp_input)input );
}

WASP_GENERIC_FORMAT( win32_pipe_input )
WASP_GENERIC_COMPARE( win32_pipe_input )
WASP_C_SUBTYPE2( win32_pipe_input, "win32-pipe-input", input );

/* win32_pipe_output */
void wasp_free_win32_pipe_output( wasp_win32_pipe_output output ){
    wasp_objfree( (wasp_object) output );
}

void wasp_trace_win32_pipe_output( wasp_win32_pipe_output output ){
    wasp_grey_obj( (wasp_object) output->conn );
}

WASP_GENERIC_FORMAT( win32_pipe_output )
WASP_GENERIC_COMPARE( win32_pipe_output )
WASP_C_SUBTYPE2( win32_pipe_output, "win32-pipe-output", output );
#endif

//TODO: UDP Server
//TODO: UDP Connect
//TODO: EvDNS Wrapper

#ifdef WASP_DEBUG_IO
void wasp_scan_pool_for_io( char* pool_name, wasp_pool pool ){
    wasp_object obj = pool->head;
    while( obj ){
        if( obj->type == wasp_os_connection_type ){
            wasp_os_connection conn = (wasp_os_connection) obj;
            printf( "    Connection " );
            if( conn->reading ) printf( "Reading, " );
            if( conn->writing ) printf( "Writing, " );
            printf( "Handle: %i\n", conn->handle );
        }else if( obj->type == wasp_os_service_type ){
            wasp_os_service svc = (wasp_os_service) obj;
            printf( "    Service " );
            printf( "Handle: %i\n", svc->handle );
        }
        obj = obj->next;
    }
}

WASP_BEGIN_PRIM( "scan-io", scan_io )
    printf( "---- SCANNING I/O ACTIVITY [%i] ----\n", wasp_os_loop_use );
    wasp_scan_pool_for_io( "root", wasp_roots );
    wasp_scan_pool_for_io( "grey", wasp_greys );
    wasp_scan_pool_for_io( "black", wasp_blacks );
    wasp_scan_pool_for_io( "white", wasp_whites );
    printf( "-------- DONE SCANNING I/O --------\n" );
WASP_END_PRIM( scan_io )

#endif

#ifdef WASP_IN_WIN32
static int windows_color_map[] = {
    //IRGB
    //8421
    0, 
    4,  // Red
    2,  // Green
    6,  // Yellow
    1,  // Blue
    5,  // Magenta
    3,  // Cyan
    7,  // White
    // Bright
    12, // Bright-Red
    10, // Bright-Green
    14, // Bright-Yellow
    9,  // Bright-Blue
    13, // Bright-Magenta
    11, // Bright-Cyan
    15,  // Bright-White
};
#endif

static void reset_console_colors( ){
#ifdef WASP_IN_WIN32
    if( ! SetConsoleTextAttribute( wasp_stdout_fd, 15 ) ){
        wasp_raise_winerror( wasp_es_vm );
    };
#else
    printf( "\033[0m" );
    fsync( STDIN_FILENO );
    fflush( stdout );
#endif
}

static void set_console_colors( int fg, int bg ){
#ifdef WASP_IN_WIN32
    fg = windows_color_map[fg];
    bg = windows_color_map[bg];

    bg = ( bg & 8 ) << 4;
    if( ! SetConsoleTextAttribute( wasp_stdout_fd, fg | bg ) ){
        wasp_raise_winerror( wasp_es_vm );
    };

    NO_RESULT( );
    //TODO
#else
#define FG ( 30 + ( fg & 7 ) )
#define BG ( 40 + ( bg & 7 ) )
// #define BG ( bg ? 40 + ( bg & 7 ) : 0 )

    if( fg == 256 ){
        if( bg != 256 ) printf( "\033[%im", BG );
    }else{
        putchar( 27 ); putchar( '[' );
        if( fg & 8 ){ 
            printf( "1;%i", FG );
        }else{ 
            printf( "%i", FG ) ;
        };

        if( bg != 256 ){ printf( ";%im", BG ); }else{ putchar( 'm' ); };
    }
    fflush( stdout );
#undef FG
#undef BG
#endif
}

/*
WASP_BEGIN_PRIM( "conso-set-attr", conio_set_attr )
    if( has_fg && wasp_is_integer( fg ) ){
        n |= wasp_integer_fv( fg );
    }else{ 
        n |= info.wAttributes & ( 
            FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED |
            FOREGROUND_INTENSITY
        );
    };

    if( has_bg && wasp_is_integer( bg ) ){
        n |= wasp_integer_fv( bg );
    }else{ 
        n |= info.wAttributes & ( 
            BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED |
            BACKGROUND_INTENSITY
        );
    };

    if( ! SetConsoleTextAttribute( wasp_stdout_fd, n ) ){
        wasp_raise_winerror( wasp_es_vm );
    };

    NO_RESULT( );
WASP_END_PRIM( conio_set_attr )
*/

WASP_BEGIN_PRIM( "reset-console-colors", reset_console_colors )
    NO_REST_ARGS( );
    fflush( stdout );
    reset_console_colors( );
#ifndef WASP_IN_WIN32
    fsync( STDOUT_FILENO );
#endif
    NO_RESULT( );
WASP_END_PRIM( reset_console_colors )

WASP_BEGIN_PRIM( "set-console-colors", set_console_colors )
    OPT_ANY_ARG( fg )
    OPT_ANY_ARG( bg )
    NO_REST_ARGS( );

    if( has_fg && wasp_is_false( fg ) ) has_fg = 0;
    if( has_bg && wasp_is_false( bg ) ) has_bg = 0;
    if( has_fg ) fg = wasp_req_integer( fg );
    if( has_bg ) bg = wasp_req_integer( bg );

    fflush( stdout );
#ifdef WASP_IN_WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;
    if( ! ( has_fg && has_bg ) ){
        if( ! GetConsoleScreenBufferInfo( wasp_stdout_fd, &info ) ){
            wasp_raise_winerror( wasp_es_vm );
        };

        if( ! has_fg ) fg = ( info.wAttributes & 15 );
        if( ! has_bg ) bg = (( info.wAttributes >> 4 ) & 7 );
    };
#else
    //TODO: Do we need to FlushFile ?
    fsync( STDOUT_FILENO );
    if( ! has_fg ) fg = 256;
    if( ! has_bg ) bg = 256;
#endif

    set_console_colors( fg, bg ); 
    NO_RESULT( );
WASP_END_PRIM( )

WASP_BEGIN_PRIM( "console-blit", console_blit )
    REQ_STRING_ARG( text )
    REQ_STRING_ARG( fg )
    REQ_STRING_ARG( bg )
    OPT_INTEGER_ARG( offset );
    OPT_INTEGER_ARG( length ); 
    
    fflush( stdout );
#ifndef WASP_IN_WIN32
    //TODO: Do we need to FlushFile ?
    fsync( STDOUT_FILENO );
#endif

    if( ! has_offset ) offset = 0;
    if( ! has_length ) length = wasp_string_length( text );
    
    if( wasp_string_length( fg ) < length ) length = wasp_string_length( fg );
    if( wasp_string_length( bg ) < length ) length = wasp_string_length( bg );
    
    if( offset >= length ) goto done;

    int c_fg = 256; 
    int c_bg = 256; 
    char* fgs = wasp_sf_string( fg );
    char* bgs = wasp_sf_string( bg );
    char* txt = wasp_sf_string( text );

    while( offset < length ){
        int n_fg = fgs[offset];
        int n_bg = bgs[offset];
        if(( c_fg != n_fg  )||( c_bg != n_bg  )){
            set_console_colors( n_fg, n_bg );
            c_bg = n_bg; c_fg = n_fg;
        };
        putchar( txt[offset++] );
    }
done:
    fflush( stdout );
#ifndef WASP_IN_WIN32
    //TODO: Do we need to FlushFile ?
    fsync( STDOUT_FILENO );
#endif

    NO_RESULT( );
WASP_END_PRIM( console_blit )

WASP_BEGIN_PRIM( "unbuffer-console", unbuffer_console )
#ifdef WASP_IN_WIN32
    // Basically, we enable absolutely nothing.
    if( ! SetConsoleMode( wasp_stdin_fd, ENABLE_EXTENDED_FLAGS ) ){
        wasp_raise_winerror( wasp_es_vm );
    }; 
#else
    struct termios cfg;
    tcgetattr( STDIN_FILENO, &cfg );
    cfmakeraw( &cfg );
    tcsetattr( STDIN_FILENO, TCSADRAIN, &cfg );
#endif
    NO_RESULT( )
WASP_END_PRIM( unbuffer_console )

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
    wasp_ss_connect = wasp_symbol_fs( "connect" );

    wasp_process p = wasp_make_poll( wasp_os_poll, wasp_vf_null( ) );
    wasp_root_obj( (wasp_object) p );
    wasp_os_loop_process = p;

    WASP_I_SUBTYPE( os_connection, connection );
    WASP_I_SUBTYPE( os_service, input );
    WASP_I_SUBTYPE( os_input, input );
    WASP_I_SUBTYPE( os_output, output );

#ifdef WASP_IN_WIN32
    WASP_I_SUBTYPE( win32_pipe_connection, connection );
    WASP_I_SUBTYPE( win32_pipe_input, input );
    WASP_I_SUBTYPE( win32_pipe_output, output );
#endif
    
    WASP_BIND_PRIM( start_tcp_connect );

    WASP_BIND_PRIM( os_connection_input );
    WASP_BIND_PRIM( os_connection_output );

    WASP_BIND_PRIM( serve_tcp );
    WASP_BIND_PRIM( resolve_ipv4 );
    
    WASP_BIND_PRIM( close_service );
#ifdef WASP_DEBUG_IO
    WASP_BIND_PRIM( scan_io );
#endif

    WASP_BIND_PRIM( unbuffer_console );

#ifdef WASP_IN_WIN32
    WASP_BIND_PRIM( conio_goto );
    WASP_BIND_PRIM( conio_cls );
    WASP_BIND_PRIM( conio_clear );
    WASP_BIND_PRIM( conio_size );
#else
    WASP_BIND_PRIM( tty_size );
#endif
   
    WASP_BIND_PRIM( reset_console_colors );
    WASP_BIND_PRIM( set_console_colors );
    WASP_BIND_PRIM( console_blit );
    wasp_set_global( wasp_symbol_fs( "*console*" ), 
                     wasp_vf_connection( wasp_make_stdio( ) ) );
}
