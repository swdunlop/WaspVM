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

#ifndef WASP_MQ_H
#define WASP_MQ_H 1

/* Used internally by channels, these mqs provide an asynchronous, in-order
 * means of transferring data. 
 * TODO: THREAD: Each mq should have a mutex.
 */

struct wasp_message_data;
typedef struct wasp_message_data* wasp_message;

/* A simple forward-linked list of pointers. */

struct wasp_message_data {
    wasp_message next;
    void* content;
};

struct wasp_mq_data;
typedef struct wasp_mq_data* wasp_mq;

/* Wraps the head andtrace,  tail of mqd messages. Maintains a refct that is
 * is used to negotiate GC.
 * TODO: THREAD: Mutex here.
 */

struct wasp_mq_data {
    wasp_quad refct;
    wasp_message first, last;
    wasp_gc_mt trace, free;
};

void wasp_mq_heap( void* obj );

void wasp_mq_gc( );

#define WASP_QUEUE_GC ((wasp_gc_mt)wasp_mq_gc)
#define WASP_QUEUE_HEAP ((wasp_gc_mt)wasp_mq_heap)

/* Creates a new message mq, with one initial reference and no messages.
 * The supplied free method should either by WASP_QUEUE_HEAP or WASP_QUEUE_GC.
 */

wasp_mq wasp_make_mq( wasp_gc_mt free );

/* Adds the supplied message pointer to the message mq.
 */

void wasp_send_message( wasp_mq q, void* data );

/* If a message is pending in the mq, updates data with the message pointer,
 * and returns nonzero.  Otherwise, returns 0. 
 */

void* wasp_next_message( wasp_mq q, void** data );

/* Indicates that an object has gained a reference to the mq.
 */

void wasp_incref_mq( wasp_mq q );

/* Indicates that an object has lost a reference to the mq, and may cause
 * the mq to be purged. 
 */

void wasp_decref_mq( wasp_mq q );

/* Meant to be called by the trace method of an object that contains a
 * reference to the mq. 
 *
 * TODO: Mark the current WHITE chain in the mq header to prevent repeated
 *       traces of the same mq. */

void wasp_trace_mq( wasp_mq q, wasp_gc_mt gc );

#endif
