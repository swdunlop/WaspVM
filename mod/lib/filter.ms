; Copyright (C) 2006, Ephemeral Security, LLC
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

"filter -- A process that waits for data from an input channel, and 
           sends data to an output channel.  Filters are constructed using
           a constructor function, then wired together using either the 
           input-chain or output-chain functions."

"input-chain -- The input-chain function, given an input channel and zero or 
                more filters, connects the filters together in such a way that 
                when a message is sent to the input channel, it will propagate
                through the filters until it arrives in a final output channel.
               
                This output channel is returned by the input-chain function."

"output-chain -- The output-chain function, given an output channel and zero 
                 or more filters, connects the filters together in such a 
                 way that when a message is sent to the input channel, it 
                 will propagate through the filters until it arrives in a 
                 final output channel.
               
                 This input channel is returned by the input-chain function."

"error-on-fail -- Given a message, raises an error if a failure was signalled,
               using the (fail info ...) or (fail info ... error) convention.
               If the later convention is used, the error's context will match
               the original context of the error."

"fail-on-error -- Given a channel and zero or more statements, guards the
               evaluation of the statements with a function that will send
               a (fail info ... error) message to the specified channel if
               an error occurs."

(module "lib/filter")
(import "lib/iterate")

(export fail-on-error error-on-fail output-chain input-chain define-filter)

;; Problems with the current model:
;;   * there's no way to detect an error on the input-chain.
;;   
;;;(define (make-mosref-transport xmit-cipher xmit-key
;;;                               recv-cipher recv-key
;;;                               xmit recv)
;;;  (list (input-chain xmit 
;;;                    (prepend-checksum-filter mosref-crc)
;;;                    (prepend-length-filter)
;;;                    (pad-message-filter (block-size xmit-key))
;;;                    (encrypt-filter xmit-cipher xmit-key))
;;;
;;;        (output-chain recv 
;;;                    (decrypt-filter recv-cipher recv-key)
;;;                    (collate-blocks-filter)
;;;                    (check-checksum-filter mosref-crc))))
            
(define (error-on-fail message)
  (if (and (pair? message) (eq? (car message) 'fail))
    (let ((err (find error? message)))
      (if err 
        (re-error err) 
        (apply error message)))
    message))

(define (output-chain xmit . filters)
  (define recv #f)
  (for-each (function (chain-filter filter)
              (define queue (make-queue))
              (set! recv (queue-input queue))

              (filter recv xmit)
              (set! xmit (queue-output queue)))
            filters)
  xmit)

(define (input-chain recv . filters)
  (define xmit #f)
  (for-each (function (chain-filter filter)
              (define queue (make-queue))
              (set! xmit (queue-output queue))
             
              (filter recv xmit)
              (set! recv (queue-input queue)))
            filters)
  recv)

(define-macro (define-filter formals . body)
  `(define ,formals
     (function (,(make-symbol 'mk- (car formals)) in out)
       (spawn (function (,(make-symbol 'run- (car formals))) 
                (fail-on-error out ,@body))))))

(define-macro (fail-on-error channel . body)
  `(guard (function (fail-for-error err)
            ;(re-error err) ;TODO: Just for debugging..
            (send (list 'fail 
                        (error-key err)
                        @(error-info err)
                        err)
                  ,channel)
            ,channel)
          ,@body))

