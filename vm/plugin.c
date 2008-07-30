/* Copyright (C) 2006, Scott W. Dunlop <swdunlop@gmail.com>
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

wasp_symbol wasp_es_plugin;

typedef void (*init_func) ();

#ifdef WASP_IN_WIN32

#include <windows.h>

void wasp_winerror( ){
    int err = GetLastError();
    static char buf[ 256 ];
    if( FormatMessageA( 
        FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, 
	NULL, err, 0, buf, sizeof( buf ), NULL ) 
    ){
	wasp_errf( wasp_es_plugin, "s", buf );
    }else{
	wasp_errf( wasp_es_plugin, "si", "windows error", err );
    }
}

void wasp_load_plugin( const char* path, const char* init ){
    HINSTANCE module;
    init_func func;  

    module = LoadLibraryA( path );

    if( ! module ) wasp_winerror( );
    func = (init_func)GetProcAddress( module, init );

    if( ! func ) wasp_winerror( );
    func();
   
    //NOTE: We do not FreeLibrary, with the assumption that pointers into the 
    //      module remain.
}

#else

#include <dlfcn.h>

void wasp_dlerror( ){
    wasp_errf( wasp_es_plugin, "s", dlerror( ) );
}

void wasp_load_plugin( const char* path, const char* init ){
    void* module;
    init_func func;
    
    module = dlopen( path, RTLD_LAZY | RTLD_GLOBAL ); 

    if( ! module ) wasp_dlerror( );
    func = ( init_func )dlsym( module, init ); 

    if( ! func ) wasp_dlerror( );
    func();

    //NOTE: We do not dlclose, with the assumption that pointers into the module
    //      remain.
}

#endif

WASP_BEGIN_PRIM( "load-subsystem", load_subsystem )
    REQ_STRING_ARG( path );
    REQ_STRING_ARG( init );
    NO_REST_ARGS( );
    
    wasp_load_plugin( wasp_sf_string( path ), wasp_sf_string( init ) );

    NO_RESULT( );
WASP_END_PRIM( load_subsystem )

void wasp_init_plugin_subsystem( ){
    wasp_es_plugin = wasp_symbol_fs( "plugin" );
    wasp_set_global( wasp_symbol_fs( "*plugin-ext*" ), 
                       wasp_vf_string( wasp_string_fs( WASP_SO ) ) );
    WASP_BIND_PRIM( load_subsystem );
}
