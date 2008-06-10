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

// For whatever reason, O_NONFOLLOW is hidden except for GNU source on GNU 
// libc platforms. Very irritating.
#define _GNU_SOURCE SORTA_KINDA_NOT_REALLY

#include "waspvm.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

extern char** environ;

wasp_boolean wasp_file_exists( wasp_string path ){
    struct stat s;

    int r = stat( wasp_sf_string( path ), &s );

    if( r == 0 ){
        return  S_ISREG( s.st_mode );
    }else{
        return 0;
    }
}

wasp_boolean wasp_dir_exists( wasp_string path ){
    struct stat s;

    int r = stat( wasp_sf_string( path ), &s );

    if( r == 0 ){
        return  S_ISDIR( s.st_mode );
    }else{
        return 0;
    }
}

wasp_string wasp_locate_util( wasp_string utilname ){
    char ** env;

    for( env = environ; *env; env ++ ){
        char* pathstr = *env;
        if( strlen( pathstr ) < 5 )continue;
        if( memcmp( pathstr, "PATH=", 5 ) )continue;

        wasp_pair tc = wasp_make_tc( );
        
        pathstr += 5;

        while( *pathstr ){
#ifdef WASP_IN_WIN32
            size_t endp = strcspn( pathstr, ";\0" ); 
#else 
            size_t endp = strcspn( pathstr, ":\0" ); 
#endif
        if( endp )wasp_tc_append( tc, wasp_vf_string( wasp_string_fm( pathstr, endp) ) );
        pathstr += endp;
        if( ! *pathstr )break;
        pathstr++;
        }

        return wasp_locate_file( utilname, wasp_list_fv( wasp_car( tc ) ) );
    };

    return NULL;
}

wasp_string wasp_locate_file( wasp_string filename, wasp_list paths ){
    struct stat s;
    wasp_quad namelen = wasp_string_length( filename );

    while( paths ){
        wasp_string path = wasp_req_string( wasp_car( paths ) );
        wasp_quad pathlen = wasp_string_length( path );
        wasp_string n = wasp_make_string( namelen + pathlen + 1 );
        wasp_string_append_str( n, path );
#ifdef WASP_IN_WIN32
        wasp_string_append_byte( n, '\\' );
#else
        wasp_string_append_byte( n, '/' );
#endif
        wasp_string_append_str( n, filename );
        
        if(( stat( wasp_sf_string( n ), &s ) == 0 )&&( S_ISREG( s.st_mode ) ))return n;
        wasp_objfree( (wasp_object)n );

        paths = wasp_req_list( wasp_cdr( paths ) );
    }

    return NULL;
}
wasp_file wasp_make_file( wasp_string path, int fd ){
    wasp_file file = WASP_OBJALLOC( file );
    file->path = path;
    file->fd = fd;
    return file;
}
void wasp_trace_file( wasp_file file ){
    wasp_grey_obj( (wasp_object) file->path );
}
void wasp_free_file( wasp_file file ){
    if( ! file->closed )close( file->fd );
    wasp_objfree( file );
}
void wasp_format_file( wasp_string buf, wasp_file file ){
    wasp_format_begin( buf, file );
    wasp_string_append_cs( buf, file->closed ? " closed" : " open" );
    if( file->path ){
        wasp_string_append_byte( buf, ' ' );
        wasp_string_append_str( buf, file->path );
    };
    wasp_format_end( buf );
}
WASP_GENERIC_COMPARE( file );
int wasp_os_error( int code ){
    if( code == -1 ){
        wasp_errf( wasp_es_vm, "si", strerror( errno ), errno );
    };
    return code;
}
wasp_string wasp_read_file( wasp_file file, wasp_quad max ){
    char buf[1024];
    wasp_string data = wasp_make_string( 1024 );
    wasp_quad total = 0;

    while( total < max ){
        wasp_quad amt = max - total;
        if( amt > 1024 ) amt = 1024;
       
        // wasp_printf( "sin", "WASP_READ_FILE: amt: ", amt );
        wasp_integer r = wasp_os_error( read( file->fd, buf, amt ) );
        if( ! r )break; // End of file..
        total += r;
        wasp_string_append( data, buf, r );
    }
    
    return data;
}
void wasp_write_file( wasp_file file, const void* data, wasp_integer datalen ){
    wasp_integer written = 0;
    while( written < datalen ){
        written += wasp_os_error( write( file->fd, data, datalen ) );     
    }        
}
void wasp_close_file( wasp_file file ){
    wasp_os_error( close( file->fd ) ); 
    file->closed = 1;
}
wasp_file wasp_open_file( const char* path, const char* flags, wasp_integer mode ){
    int flag = 0;
#ifdef WASP_IN_WIN32
    flag |= O_BINARY;
    // Let's not have any magic line ending conversions screwing up seek, 
    // tyvm.
#endif
    int w = 0, r = 0;

    while( *flags ){
        switch( *(flags++) ){
        case 'r':
            r = 1;
            if( w ){
                flag ^= O_WRONLY;
                flag |= O_RDWR;
            }else{
                flag |= O_RDONLY;
            };
            break;
        case 'w':
            w = 1;
            if( r ){
                flag ^= O_RDONLY;
                flag |= O_RDWR;
            }else{
                flag |= O_WRONLY;
            };
            break;
        case 'c':
            flag |= O_CREAT;
            break;
        case 'a':
            flag |= O_APPEND;
            break;
        case 't':
            flag |= O_TRUNC;
            break;
#ifdef WASP_IN_WIN32
    //The core WIN32 headers don't provide NONBLOCK or SYNC.
        case 'n':
        case 's':
            break;
#else
        case 'n':
            flag |= O_NONBLOCK;
            break;
        case 's':
            flag |= O_SYNC;
            break;
#if defined( WASP_IN_WIN32 )||defined( WASP_IN_LINUX )
        //Neither Linux or Cygwin support implied locking.
        case 'l':
        case 'L':
            break;
#else
        case 'l':
            flag |= O_SHLOCK;
            break;
        case 'L':
            flag |= O_EXLOCK;
            break;
#endif
#endif
#ifdef WASP_IN_WIN32
        // ||defined( WASP_IN_LINUX )
        //Additionally, Cygwin doesn't do NOFOLLOW since windows lacks
        //symlinks.
        case 'f': 
            break;
#else
        case 'f':
            flag |= O_NOFOLLOW;
            break;
#endif
        case 'e':
            flag |= O_EXCL;
            break;
        case 0:
            break;
        default:
            wasp_errf( 
                wasp_es_vm, "ss", "unrecognized flag encountered in flags", 
                flags
            );    
        };
    };

    return wasp_make_file( 
        wasp_string_fs( path ), 
        wasp_os_error( open( path, flag, mode ) ) 
    );
}

WASP_BEGIN_PRIM( "open-file", open_file )
    REQ_STRING_ARG( path );
    REQ_STRING_ARG( flags );
    OPT_INTEGER_ARG( mode );
    NO_REST_ARGS( )
    const char* fp = wasp_sf_string( flags );

    int i, fl = wasp_string_length( flags );
    
    FILE_RESULT( wasp_open_file( wasp_sf_string( path ), wasp_sf_string( flags ), 
                                has_mode ? mode : 0600 ) );
WASP_END_PRIM( open_file )

WASP_BEGIN_PRIM( "file-len", file_len )
    REQ_FILE_ARG( file );
    NO_REST_ARGS( );
    
    wasp_integer pos = wasp_os_error( lseek( file->fd, 0, SEEK_CUR ) );
    wasp_integer len = wasp_os_error( lseek( file->fd, 0, SEEK_END ) );
    wasp_os_error( lseek( file->fd, pos, SEEK_SET ) );   

    RESULT( wasp_vf_integer( len ) );
WASP_END_PRIM( file_len )

WASP_BEGIN_PRIM( "read-file", read_file )
    REQ_FILE_ARG( file );
    OPT_INTEGER_ARG( quantity );
    NO_REST_ARGS( );

    if( ! has_quantity )quantity = WASP_MAX_IMM; 
    // wasp_printf( "sisxn", "READ-FILE, quantity: ", quantity, " file: ", file );
    wasp_string data = wasp_read_file( file, quantity );
    wasp_value result;

    if( quantity && (! wasp_string_length( data ) ) ){
        result = wasp_vf_false( );
    }else{
        result = wasp_vf_string( data );
    }
    
    RESULT( result );
WASP_END_PRIM( read_file )

WASP_BEGIN_PRIM( "close-file", close_file )
    REQ_FILE_ARG( file );
    NO_REST_ARGS( );
    
    wasp_close_file( file );

    NO_RESULT( );
WASP_END_PRIM( close_file )

WASP_BEGIN_PRIM( "closed-file?", closed_fileq )
    REQ_FILE_ARG( file );
    NO_REST_ARGS( );
    RESULT( wasp_vf_boolean( file->closed ) ); 
WASP_END_PRIM( closed_fileq )

WASP_BEGIN_PRIM( "write-file", write_file )
    REQ_FILE_ARG( file );
    REQ_STRING_ARG( data );
    NO_REST_ARGS( )
   
    wasp_write_file( file, wasp_sf_string( data ), wasp_string_length( data ) );
    
    NO_RESULT( )
WASP_END_PRIM( write_file )

WASP_BEGIN_PRIM( "file-skip", file_skip )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );

    offset = wasp_os_error( lseek( file->fd, offset, SEEK_CUR ) );

    RESULT( wasp_vf_integer( offset ) );
WASP_END_PRIM( file_skip )

WASP_BEGIN_PRIM( "file-pos", file_pos )
    REQ_FILE_ARG( file );
    NO_REST_ARGS( );

    wasp_integer offset = wasp_os_error( lseek( file->fd, 0, SEEK_CUR ) );

    RESULT( wasp_vf_integer( offset ) );
WASP_END_PRIM( file_pos )

WASP_BEGIN_PRIM( "file-seek", file_seek )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );
    
    if( offset < 0 ){
        offset = lseek( file->fd, offset + 1, SEEK_END );
    }else{
        offset = lseek( file->fd, offset, SEEK_SET );
    };

    wasp_os_error( offset );

    RESULT( wasp_vf_integer( offset ) );
WASP_END_PRIM( file_seek )

WASP_C_TYPE( file );

void wasp_init_file_subsystem( ){
    WASP_I_TYPE( file );

#if defined(_WIN32)||defined(__CYGWIN__)
    wasp_set_global( wasp_symbol_fs( "*path-sep*" ), 
                    wasp_vf_string( wasp_string_fs( "\\" ) ) );
    wasp_set_global( wasp_symbol_fs( "*line-sep*" ),
                    wasp_vf_string( wasp_string_fs( "\r\n" ) ) );
#else
    wasp_set_global( wasp_symbol_fs( "*path-sep*" ),
                    wasp_vf_string( wasp_string_fs( "/" ) ) );
    wasp_set_global( wasp_symbol_fs( "*line-sep*" ),
                    wasp_vf_string( wasp_string_fs( "\n" ) ) );
#endif

    WASP_BIND_PRIM( open_file );
    WASP_BIND_PRIM( close_file );
    WASP_BIND_PRIM( closed_fileq );
    WASP_BIND_PRIM( fileq );
    WASP_BIND_PRIM( read_file );
    WASP_BIND_PRIM( write_file );
    WASP_BIND_PRIM( file_skip );
    WASP_BIND_PRIM( file_seek );
    WASP_BIND_PRIM( file_pos );
    WASP_BIND_PRIM( file_len );
}

