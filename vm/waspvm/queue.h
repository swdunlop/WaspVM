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

#ifndef WASP_QUEUE_H
#define WASP_QUEUE_H 1

/* Queue input channels are input channels that fetch values from the wrapped
 * message queue.
 */

WASP_BEGIN_SUBTYPE( input, queue_input )
    void* queue;
WASP_END_SUBTYPE( queue_input );

/* Queue output channels are output channels that add values to the wrapped
 * message queue.
 */

WASP_BEGIN_SUBTYPE( output, queue_output )
    void* queue;
WASP_END_SUBTYPE( queue_output );

/* The queue, in waspvm, is the replacement for the old Mosquito channels;
 * it wraps a primitive message queue, and provides an input and output
 * channel that interacts with that queue.
 */

WASP_BEGIN_TYPE( queue )
    wasp_mq mq;
    wasp_queue_input input;
    wasp_queue_output output;
WASP_END_TYPE( queue );

#define REQ_QUEUE_ARG( x ) REQ_TYPED_ARG( x, queue )
#define OPT_QUEUE_ARG( x ) OPT_TYPED_ARG( x, queue )
#define QUEUE_RESULT( x )  TYPED_RESULT( queue, x )

/* Creates a new queue, and all of the ancilliary objects wrapped by the queue.
 */

wasp_queue wasp_make_queue( );

/* Initializes the queue type, and binds primitives that manage queues. */

void wasp_init_queue_subsystem( );

#endif
