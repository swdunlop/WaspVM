/* Copyright (C) 2006, Ephemeral Security, LLC
 * With modifications Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

//TODO: We really need a time type.
WASP_BEGIN_PRIM( "path-mtime", path_mtime )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );

    struct stat s;

    wasp_os_error( stat( wasp_sf_string( path ), &s ) );

#if defined( WASP_IN_LINUX )||defined( WASP_IN_WIN32 )
    time_t mtime = s.st_mtime;
#else
    time_t mtime = s.st_mtimespec.tv_sec;
#endif

    RESULT( wasp_vf_integer( mtime ) );
WASP_END_PRIM( path_mtime )

WASP_BEGIN_PRIM( "locate-path", locate_path )
    REQ_STRING_ARG( filename );
    REST_ARGS( paths );
    
    wasp_string s = wasp_locate_file( filename, paths );

    if( s ){
        STRING_RESULT( s );
    }else{
        FALSE_RESULT( );
    };
WASP_END_PRIM( locate_path )

WASP_BEGIN_PRIM( "path-exists?", path_existsq )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );

    struct stat s;
    
    RESULT( wasp_vf_boolean( stat( wasp_sf_string( path ), &s ) == 0 ) );
WASP_END_PRIM( path_existsq )

WASP_BEGIN_PRIM( "dir-path?", dir_pathq )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );

    BOOLEAN_RESULT( wasp_dir_exists( path ) );
WASP_END_PRIM( file_pathq )

WASP_BEGIN_PRIM( "file-path?", file_pathq )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );

    BOOLEAN_RESULT( wasp_file_exists( path ) );
WASP_END_PRIM( file_pathq )

WASP_BEGIN_PRIM( "dir-files", dir_files )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );
    
    DIR* dir = opendir( wasp_sf_string( path ) );
    if( ! dir ) wasp_errf( wasp_es_vm, "sx", "cannot open directory", path );
    
    wasp_tc tc = wasp_make_tc( );
    
    for(;;){
        struct dirent* ent = readdir( dir );
        if( ! ent ) break;
        wasp_tc_add( tc, wasp_vf_string( wasp_string_fs( ent->d_name ) ) );
    };

    closedir( dir );

    RESULT( wasp_car( tc ) );
WASP_END_PRIM( dir_files )

WASP_BEGIN_PRIM( "rename-file", rename_file )
    REQ_STRING_ARG( old_path );
    REQ_STRING_ARG( new_path );
    NO_REST_ARGS( ); 

    wasp_os_error( rename( wasp_sf_string( old_path ), 
                           wasp_sf_string( new_path ) ) );

    NO_RESULT( );
WASP_END_PRIM( rename_file );

WASP_BEGIN_PRIM( "remove-file", remove_file )
    REQ_STRING_ARG( path );
    NO_REST_ARGS( ); 
   
    wasp_os_error( remove( wasp_sf_string( path ) ) );

    NO_RESULT( );
WASP_END_PRIM( rename_file );

void wasp_init_filesystem_subsystem( ){
    WASP_BIND_PRIM( path_mtime );
    WASP_BIND_PRIM( path_existsq );
    WASP_BIND_PRIM( file_pathq );
    WASP_BIND_PRIM( locate_path );

    WASP_BIND_PRIM( dir_files );
    WASP_BIND_PRIM( dir_pathq );
    WASP_BIND_PRIM( rename_file );
    WASP_BIND_PRIM( remove_file );
}
