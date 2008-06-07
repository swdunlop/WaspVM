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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "waspvm.h"

#ifdef _WIN32
// We need hton and ntoh
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define GLUESIG		"wvf1"
#define GLUELEN		4

typedef struct { 
    wasp_word size; 
    char sig[GLUELEN]; 
} glue_data;

void cannot(const char* what, const char* name){
    fprintf(stderr,"cannot %s %s: %s\n",what,name,strerror(errno));
    exit(EXIT_FAILURE);
}

wasp_word copy( const char* inname, FILE* out, const char* outname ){
    FILE* in = fopen( inname, "rb" );
    if( in == NULL ) cannot( "open", inname);

    if( fseek( in, 0, SEEK_END ) != 0 )cannot( "seek", inname );
    wasp_word insize=ftell( in );

    if( fseek( in, 0, SEEK_SET ) !=0 )cannot( "seek", inname );

    for(;;){
        char b[BUFSIZ];
        int n = fread( &b, 1, sizeof( b ), in );
        if( n == 0 ){
            if( ferror( in ) ){
                cannot( "read", inname );
            }else{
                break;
            }
        }
        if( fwrite( &b, n, 1, out )!=1 )cannot( "write", outname );
    }
    
    if( fclose( in ) != 0 )cannot( "close", inname );

    return insize;
}

void glue( const char* fragname, FILE* out, const char* outname ){
    wasp_word fragsize=copy( fragname, out, outname );

    glue_data data = { htons( fragsize ), GLUESIG };

    if( fwrite( &data, sizeof( data ), 1, out )!=1 )cannot( "write", outname );
}

int main(int argc, char* argv[]){
    if( argc < 4 ){
        fprintf( stderr, "usage: waspld stub frag0 frag1 ... result\n" );
        return 1;
    }
    
    const char* stubname = argv[ 1 ];
    const char* destname = argv[ argc - 1 ];

    argv = argv + 2;
    argc = argc - 3;

    FILE* dest = fopen( destname, "wb" );
    if( dest == NULL )cannot( "open", destname );
    
    copy( stubname, dest, destname );
   
    // This ensures that even if the impossible happens, the binary ends in
    // GLUESIG, we don't accidentally try to unglue it.
    int i, block = 0;
    if( fwrite( &block, sizeof( block ), 1, dest ) != 1 ){
        cannot( "write", destname );
    }
     
    for( i = 0; i < argc; i ++ ){
	printf( "Gluing %s to %s..\n", argv[i], destname );
        glue( argv[i], dest, destname );
    }

    if( fclose( dest ) != 0 )cannot( "close", destname );

    return 0;
}
