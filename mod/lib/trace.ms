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

(module "lib/trace")
(import "lib/filter")

(define-macro (trace . stmts)
    `(guard (lambda (err) (disable-trace)
                          (re-error err))
            (enable-trace)
            (let ((%x (begin ,@stmts)))
              (disable-trace)
              %x)))

(define-macro (trap . stmts)
    `(guard (lambda (err) err) ,@stmts))

(define-filter (trace-filter tag)
    (forever 
      (define msg (wait-input in))
      (print (string-append tag ": " 
                            ;(if (string? msg)
                            ;  (string-append (format (string-length msg))
                            ;                 " / ")
                            ;  "")
                            (format msg) *line-sep*))
      (send-output msg out)))

(export trace trap trace-filter)
