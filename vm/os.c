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
//TODO: Win32 incompat alert!
#include <unistd.h>
#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#endif
#include <errno.h>

wasp_process wasp_os_loop_process;
unsigned int wasp_os_loop_use = 0;

void wasp_enable_os_loop( ){
    printf( "OS Loop Enabled, Use Ct: %i\n", wasp_os_loop_use + 1 );
    if( wasp_os_loop_use ++ ) return;
    wasp_enable_process( wasp_os_loop_process );
}

void wasp_disable_os_loop( ){
    printf( "OS Loop Disabled, Use Ct: %i\n", wasp_os_loop_use - 1 );
    if( -- wasp_os_loop_use ) return;
    wasp_disable_process( wasp_os_loop_process );
}

void wasp_activate_os_loop( ){ 
#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
    event_loop( EVLOOP_NONBLOCK | EVLOOP_ONCE );
#endif
	if( ! wasp_os_loop_process->enabled ) wasp_proc_loop( );
}
void wasp_deactivate_os_loop( ){ }

void wasp_os_start_writing( wasp_os_connection conn, wasp_string data ){
    char* str = wasp_sf_string( data );
    int   len = wasp_string_length( data );
    
    if( ! conn->writing ){
        printf( "Started writing for connection %x\n", conn );
        //TODO: Try writing directly, first.. Sometimes it works!
        conn->writing = 1;
        wasp_enable_os_loop( );
        wasp_root_obj( (wasp_object) conn );
    }
    
#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
    bufferevent_write( conn->event, str, len );
#endif
}

void wasp_os_start_reading( wasp_os_connection conn ){
    if( conn->reading ) return;
    printf( "Started reading for connection %x\n", conn );
    
    conn->reading = 1;
    wasp_enable_os_loop( );
    bufferevent_enable( conn->event, EV_READ );
}

void wasp_os_stop_writing( wasp_os_connection conn ){
    if( ! conn->writing ) return;
    printf( "Stopped writing for connection %x\n", conn );
    conn->writing = 0;
    wasp_disable_os_loop( );
    wasp_unroot_obj( (wasp_object) conn );
}

void wasp_os_stop_reading( wasp_os_connection conn ){
    if( ! conn->reading ) return;
    printf( "Stopped reading for connection %x\n", conn );
    conn->reading = 0;
    wasp_disable_os_loop( );
}


void wasp_os_closed( wasp_os_connection conn ){
    if( conn->state < WASP_CLOSED ){
        close( conn->handle );
        conn->state = WASP_CLOSED;
        
        wasp_wake_all_monitors( 
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

#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
wasp_string wasp_read_bufferevent( struct bufferevent* ev ){
    static char data[4096];
    int len = bufferevent_read( ev, data, sizeof( data ) );
    if( ! len ) return NULL;
    wasp_string str = wasp_string_fm( data, len );

    //TODO: There's an extra copy op, here.

    return str;
}
#endif

int wasp_os_recv_mt( wasp_os_input inp, wasp_value* data ){
    wasp_os_connection conn = inp->conn;
    
    if( conn->state >= WASP_CLOSING ){
        *data = wasp_vf_symbol( wasp_ss_close );
        return 1;
    }

#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
    wasp_string str = wasp_read_bufferevent( inp->conn->event );  
    if( ! str ){
        wasp_os_start_reading( conn );
        return 0;
    }

    *data = wasp_vf_string( str );
#endif

    return 1;
}

#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else

void wasp_os_read_cb( 
    struct bufferevent* ev, wasp_os_connection conn 
){
    wasp_os_input input = (wasp_os_input)(((wasp_connection)conn)->input);
    if( ! wasp_input_monitored( (wasp_input) input ) ) return;
    wasp_string str = wasp_read_bufferevent( ev );  
    if( ! str ) return;
    wasp_os_stop_reading( conn );
    bufferevent_disable( conn->event, EV_READ );
    wasp_wake_monitor( (wasp_input)input, wasp_vf_string( str ) );
}

void wasp_os_error_cb( 
    struct bufferevent* ev, short what, wasp_os_connection conn 
){
    wasp_os_closed( conn );
    printf( "OS Error on %i: %i\n", conn->handle, what );
    //TODO: Probably need to store a symbol describing the real error..
}

#endif

int wasp_svc_recv_mt( wasp_os_service svc, wasp_value* data ){
    if( svc->closed ){
        *data = wasp_vf_symbol( wasp_ss_close );
        return 1;
    }else{
        wasp_enable_os_loop( );
#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
        event_add( &( svc->event ), svc->timeout ? &( svc->timeval ) : NULL );
#endif
        return 0;
    }
}

#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
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
#endif

wasp_os_service wasp_make_os_service( int handle ){
    wasp_os_service svc = WASP_OBJALLOC( os_service );
    ((wasp_input)svc)->recv = (wasp_input_mt)wasp_svc_recv_mt;
    
    svc->timeout = svc->closed = 0;
#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
    svc->timeval.tv_sec = svc->timeval.tv_usec = 0;
    event_set( &( svc->event ), handle, EV_READ, wasp_svc_read_cb, (void*)svc );
#endif
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
#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
    oscon->event = bufferevent_new( handle, 
                                    (evbuffercb) wasp_os_read_cb, 
                                    NULL, //TODO:WRITE-COMPLETION
                                    (everrorcb) wasp_os_error_cb, 
                                    oscon);
    bufferevent_enable( oscon->event, EV_WRITE );
#endif
    wasp_root_obj( (wasp_object) oscon ); //TODO: Needs unroot on close.

    return oscon;
}
 
void wasp_report_host_error( ){
#ifdef WASP_IN_WIN32
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

int wasp_parse_dotted_quad( wasp_string quad, wasp_integer* addr ){
    wasp_byte* bytes = (wasp_byte*)addr;

    int ct = 0;
    const char* ptr = wasp_sf_string( quad );
    const char* tail = ptr + wasp_string_length( quad );
    char* next; 

    while(( ct < 4 )&&( ptr != tail )){
        wasp_quad x = strtoul( ptr, &next, 10 );  
        if( ptr == next ) break; // *ptr wasn't a digit
        if(( x > 255 )||( x < 0 )) return 0; // Not a byte.
        bytes[ ct ++ ] = (wasp_byte)x; // Otherwise, we've got one more byte.
        ptr = next;              // Advance our base-pointer.
        if( *ptr != '.' ) break; // A dot indicates we've got another quad
        ptr ++;
    }
    
    if( ct != 4 ) return 0;        // Not enough bytes were found.
    if( ptr != tail ) return 0; // Not all of the string was parsed.

    *addr = ntohl( *addr );
    return 1;
}

wasp_integer wasp_resolve( wasp_string name ){
    wasp_integer addr;

    if( ! wasp_parse_dotted_quad( name, &addr ) ){
        struct hostent *entry = gethostbyname( wasp_sf_string( name ) );
        if( !entry ){
            wasp_report_host_error( );
            //TODO }else if( entry->h_addrtype != ... ){
            //TODO: Signal an error.
        }else if( entry->h_length != 4 ){
            //TODO: Signal an error.
        }else{
            //TODO: A better version of resolve would return a list of
            //      addresses..
            addr = ntohl( *(wasp_integer*)(entry->h_addr) );
        }
    }

    return addr;
}

wasp_os_connection wasp_tcp_connect( wasp_integer host, wasp_integer port ){
    //TODO: Should I be nonblocking, here?
    struct sockaddr_in addr;
    int fd;
   
    //TODO: Move this to use getaddrinfo.
    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    addr.sin_addr.s_addr = htonl( host );

    if( ( fd = socket( AF_INET, SOCK_STREAM, 0 ) ) == -1 ){
        wasp_errf( wasp_es_vm, "s", "could not create file descriptor" );
    }

    if( connect( fd, (struct sockaddr*)&addr, sizeof(addr) ) == -1 ){
        wasp_errf( wasp_es_vm, "sii", "could not connect", host, port );
    }

    return wasp_make_os_connection( fd );
}

#ifndef WASP_USE_SYNC_TERM    
wasp_input wasp_stdin;
wasp_output wasp_stdout;

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
#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
    bufferevent_free( oscon->event );
#endif
    wasp_objfree( (wasp_object) oscon );
}

WASP_GENERIC_TRACE( os_connection )
WASP_GENERIC_FORMAT( os_connection )
WASP_GENERIC_COMPARE( os_connection )

WASP_C_SUBTYPE2( os_connection, "os-connection", connection );

wasp_free_os_service( wasp_os_service svc ){ 
#ifdef WASP_IN_WIN32
//TODO:WIN32:IO
#else
    event_del( &(svc->event) ); 
#endif
    wasp_objfree( (wasp_object) svc );
}

WASP_GENERIC_TRACE( os_service )
WASP_GENERIC_FORMAT( os_service )
WASP_GENERIC_COMPARE( os_service )

WASP_C_SUBTYPE2( os_service, "os-service", input );

void wasp_trace_os_input( wasp_os_input input ){ 
    wasp_grey_obj( (wasp_object) input->conn );
}

WASP_GENERIC_FREE( os_input )
WASP_GENERIC_FORMAT( os_input )
WASP_GENERIC_COMPARE( os_input )

WASP_C_SUBTYPE2( os_input, "os-input", input );

void wasp_trace_os_output( wasp_os_output output ){ 
    wasp_grey_obj( (wasp_object) output->conn ); 
}

WASP_GENERIC_FREE( os_output )
WASP_GENERIC_FORMAT( os_output )
WASP_GENERIC_COMPARE( os_output )

WASP_C_SUBTYPE2( os_output, "os-output", output );

WASP_BEGIN_PRIM( "resolve-ipv4", resolve_ipv4 )
    REQ_STRING_ARG( name );
    NO_REST_ARGS( );

    INTEGER_RESULT( wasp_resolve( name ) );
WASP_END_PRIM( resolve_ipv4 )

WASP_BEGIN_PRIM( "tcp-connect", tcp_connect )
    REQ_INTEGER_ARG( addr );
    REQ_INTEGER_ARG( portno );
    NO_REST_ARGS( );

    RESULT( wasp_vf_os_connection( wasp_tcp_connect( addr, portno ) ) );
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
//TODO:WIN32:IO
#else
    event_init( );
#endif
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
    WASP_BIND_PRIM( resolve_ipv4 );

    WASP_BIND_PRIM( os_connection_input );
    WASP_BIND_PRIM( os_connection_output );

    WASP_BIND_PRIM( serve_tcp );

#ifndef WASP_USE_SYNC_TERM    
    wasp_set_global( wasp_symbol_fs( "*console*" ), 
                     wasp_vf_connection( wasp_make_stdio( ) ) );
#endif
}
