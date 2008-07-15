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

#ifndef WASP_MOSVM_H
#define WASP_MOSVM_H 1

#ifdef __linux__
#define WASP_IN_LINUX LINUX_IS_NOT_XOPEN_UNIX
#endif

#ifdef __CYGWIN__
#define WASP_IN_CYGWIN A_LITTLE_UNIX_IS_A_DANGEROUS_THING
#endif

#ifdef __MINGW32__
#define WASP_IN_MINGW BUT_NONE_AT_ALL_IS_DEFINITELY_WORSE
#endif

#if defined( _WIN32 )||defined( WASP_IN_CYGWIN )||defined( WASP_IN_MINGW )
#define WASP_IN_WIN32 WELCOME_TO_SCHIZOPHRENIA_LAND
#endif

#include "waspvm/memory.h"
#include "waspvm/number.h"
#include "waspvm/boolean.h"
#include "waspvm/list.h"
#include "waspvm/tree.h"
#include "waspvm/string.h"
#include "waspvm/vector.h"
#include "waspvm/primitive.h"
#include "waspvm/procedure.h"
#include "waspvm/closure.h"
#include "waspvm/parse.h"
#include "waspvm/print.h"
#include "waspvm/format.h"
#include "waspvm/file.h"
#include "waspvm/package.h"
#include "waspvm/vm.h"
#include "waspvm/process.h"
#include "waspvm/mq.h"
#include "waspvm/channel.h"
#include "waspvm/connection.h"
#include "waspvm/error.h"
#include "waspvm/tag.h"
#include "waspvm/multimethod.h"
#include "waspvm/file.h"
#include "waspvm/time.h"
#include "waspvm/plugin.h"
#include "waspvm/queue.h"
#include "waspvm/os.h"

void wasp_init_wasp( );
void wasp_init_crc32_subsystem( );
void wasp_init_shell_subsystem( );
void wasp_bind_core_prims( );
wasp_value wasp_make_mote( wasp_type type );
void wasp_handle_sigint( int sig );
wasp_string wasp_find_arg0( int argc, const char** argv );

extern int wasp_argc;
extern wasp_list wasp_argv;
extern int wasp_abort_on_error;
extern int wasp_show_globals;
extern wasp_input wasp_stdin;
extern wasp_output wasp_stdout;

extern wasp_symbol wasp_ss_main;

#endif
