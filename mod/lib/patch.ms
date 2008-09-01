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

(module "lib/patch")

; Given a pair of channels, xmit and recv, spawns a process that relays all
; data received by xmit to recv.

(define (preface-input data in)
  (define q (make-queue))
  (send data q)
  (patch in q)
  (input q))

(define (preface-connection data conn)
  (make-connection (preface-input data conn) (output conn)))

(define (patch in out)
  (set! in (input in))
  (set! out (output out))
  (spawn (function (patch-process)
           (forever
             (define evt (wait in))
             (send evt out)
             (when (eq? evt 'close) 
               (return))))))

(define (patch2 left right)
  (patch left right)
  (patch right left))

(export patch patch2 preface-input preface-connection)
