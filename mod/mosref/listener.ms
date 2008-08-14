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

(define *listeners-by-portno* (dict))
(define *preamble-len* 16)

(define-record-type mosref-listener
                    (make-mosref-listener-state portno sessions) ;addr
                    mosref-listener?
                    (portno mosref-listener-portno)
                    (sessions mosref-listener-sessions))

(define (monitor-mosref-listener state)
  (define sessions (mosref-listener-sessions state))
  (define portno (mosref-listener-portno state))
  (define listener (tcp-listen portno))

  (define (spawn-checker conn)
    (define timer (timeout 5000 (output conn) 'timeout))
    (spawn (lambda ()
             (forever
               (define buf (make-string))
               (define evt (wait conn))
               (unless (string? evt)
                 (send 'close conn)
                 (cancel-timeout timer)
                 (return))
               (string-append! buf evt)
               (when (>= (string-length buf) *preamble-len*)
                 (define preamble (string-read! buf *preamble-len*))
                 (define channel (dict-ref sessions preamble))

                 (unless channel
                   (send 'close conn)
                   (cancel-timeout timer)
                   (return))

                 (unless (empty-string? buf)
                   (channel-prepend! (output conn) buf))

                 (dict-remove! sessions preamble)

                 (send conn channel)
                 (cancel-timeout timer)
                 (return))))))
  
  (spawn (function (monitor-mosref-listener)
            (forever 
              (define evt (wait listener))
              (when (eq? evt 'close) 
                (return))
              (spawn-checker evt)))))

(define (register-mosref-listener portno)
  (define state (make-mosref-listener-state portno (dict)))
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
  (define channel (make-channel))
  (define listener (spawn-mosref-listener portno))
  (define sessions (mosref-listener-sessions listener))
  (dict-set! sessions sin channel)
  (wait channel))

(export make-mosref-sin mosref-sin-listen)

