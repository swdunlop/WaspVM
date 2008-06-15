; Copyright (C) 2007, Scott W. Dunlop <swdunlop@gmail.com>
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

(define (send (#t message))
  (send message (current-output)))

(define (send (#t message) dest)
  (if (output? dest)
    (send-output message dest)
    (send message (output dest))))

(define (wait)
  (wait (current-input)))

(define (wait (#t src))
  (if (input? src)
    (wait-input src)
    (wait (input src))))
    
(define (input)
  (input (current-process-input)))

(define (input (<input> i))
  i)

(define (input (<queue> q))
  (queue-input q))

(define (input (<connection> c))
  (connection-input c))

(define (input (<process> q))
  (queue-input q))
  
(define (output)
  (output (current-process-output)))

(define (output (<output> o))
  o)

(define (output (<queue> q))
  (queue-output q))

(define (output (<connection> c))
  (connection-output c))

(define (output (<process> q))
  (queue-output q))

