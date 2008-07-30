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

(module "lib/s-filter")
(import "lib/filter")
(import "lib/iterate")
(import "lib/options")

(define-option :prompt0)
(define-option :promptN)
(define-option :errfn)

(export :prompt0 :promptN :errfn)

(define-filter (s-filter . opts)
  (define prompt0 (option opts :prompt0 #f))
  (define promptN (option opts :promptN #f))
  (define errfn (option opts :errfn #f))

  (define ct 0)
  (define buf (make-string 80)) 
  
  (define (parse)
    (guard (function (handle-parse-err err)
             (define key (error-key err))
             (define info (error-info err))
             (case key
               ((inc) (string-append! buf *line-sep*))
               ((and parse errfn) (errfn err)
                                  (flush-string buf))
               (else (traceback err))))
       (send-output (string->exprs buf) out)
       (flush-string buf)))

  (forever
    (cond 
      ((empty-string? buf) (if prompt0 (send-output prompt0)))
      (promptN (send-output promptN)))

    (define next (wait-input in))

    (if (string? next)
      (begin 
        (string-append! buf next)
        (parse))
      (send-output next out))))

(export s-filter)
