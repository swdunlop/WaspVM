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

#ifndef WASP_FILE_H
#define WASP_FILE_H 1

WASP_BEGIN_TYPE( file );
    wasp_string path;
    wasp_integer fd;
    wasp_boolean closed;
WASP_END_TYPE( file );

wasp_file wasp_make_file( wasp_string path, int fd );

void wasp_init_file_subsystem( );

int wasp_os_error( int code );
wasp_string wasp_read_file( wasp_file file, wasp_quad max );
void wasp_write_file( wasp_file file, const void* data, wasp_integer datalen );
void wasp_close_file( wasp_file file );
wasp_file wasp_open_file( const char* path, const char* flags, wasp_integer mode );

wasp_boolean wasp_file_exists( wasp_string filename );
wasp_string wasp_locate_file( wasp_string filename, wasp_list paths );
wasp_string wasp_locate_util( wasp_string utilname );

#define REQ_FILE_ARG( vn  ) REQ_TYPED_ARG( vn, file );
#define OPT_FILE_ARG( vn  ) OPT_TYPED_ARG( vn, file );
#define FILE_RESULT( x  ) TYPED_RESULT( file, x );

#endif
