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

(module "mosref/listener")
(import "lib/buffer-input")
(import "lib/patch")
(import "lib/record")

(define *listeners-by-portno* (make-dict))
(define *preamble-len* 16)

(define-record-type mosref-listener
                    (make-mosref-listener-state portno sessions) ;addr
                    mosref-listener?
                    (portno mosref-listener-portno)
                    (sessions mosref-listener-sessions))

(define (monitor-mosref-listener state)
  (define sessions (mosref-listener-sessions state))
  (define portno (mosref-listener-portno state))
  (define listener (serve-tcp portno))
  
  (define (mosref-sin-checker conn)
    (define read (buffer-input conn 5000))
    (define preamble (read *preamble-len*))

    (unless (string? preamble)
      ; You have 5 seconds to send a preamble.. Otherwise, it's the plank!
      (print "Rejecting preamble, took too long or closed.\n")
      (send 'close conn)
      (return))

    (define channel (dict-ref sessions preamble))

    (unless channel
      ; Perhaps I should have specified a VALID preamble?
      (print "Rejecting preamble, was invalid.\n")
      (send 'close conn)
      (return))

    (dict-remove! sessions preamble)

    ;TODO: Figure out how to put data "back" into the channel.
    ;      That will permit us to not have to do this:
    (send (preface-connection (read 'rest) conn) channel))
  
  (spawn (function (monitor-mosref-listener)
            (forever 
              (define evt (wait listener))
              (when (eq? evt 'close) 
                (return))
              (spawn mosref-sin-checker evt)))))

(define (register-mosref-listener portno)
  (define state (make-mosref-listener-state portno (make-dict)))
  (monitor-mosref-listener state)
  (dict-set! *listeners-by-portno* portno state)
  state)

(define (find-mosref-listener portno)
  (dict-ref *listeners-by-portno* portno))

(define (spawn-mosref-listener portno)
  (or (find-mosref-listener portno)
      (register-mosref-listener portno)))

(define (make-mosref-sin portno)
  (define listener (spawn-mosref-listener portno))
  (define sessions (mosref-listener-sessions listener))

  (forever
    (define preamble (read-prng *preamble-len*))
    (unless (dict-set? sessions preamble)
      (dict-set! sessions preamble #f)
      (return preamble))))

(define (mosref-sin-listen portno sin)
  (define channel (make-queue))
  (define listener (spawn-mosref-listener portno))
  (define sessions (mosref-listener-sessions listener))
  (dict-set! sessions sin channel)
  (wait channel))

(export make-mosref-sin mosref-sin-listen)

