; Copyright (C) 2006, Ephemeral Security, LLC
; Modifications (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
; 
; This library is free software; you can redistribute it and/or modify it 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
; 
; This library is distributed in the hope that it will be useful, but WITHOUT 
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
; for more details.
; 
; You should have received a copy of the GNU Lesser General Public License 
; along with this library; if not, write to the Free Software Foundation, 
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

(module "lib/shuffle")

; A Fisher-Yates Shuffle -- The F-Y shuffle is as strong as our PRNG, but 
; expensive with containers that do not have constant time access.

(define (shuffle/list l)
  (vector->list (shuffle/vector (list->vector l))))

(define (shuffle/vector v)
  (define left 0)
  (define last (- (vector-length v) 1))
  (while (< left last)
    (define right (random-integer left last))
    (define x (vector-ref v left))
    (vector-set! v left (vector-ref v right))
    (vector-set! v right x)
    (set! left (+ left 1)))
  v)

(define (shuffle x)
  (if (list? x)
    (shuffle/list x)
    (shuffle/vector x)))

